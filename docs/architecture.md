# irrd-ng architecture

This is the why behind irrd-ng: what it is, how it's put together, and where we deliberately went a different way from IRRd v4. If you just want the list of places where the *behaviour* differs from v4, that's `docs/divergences.md`. This document is about the insides, which are allowed to be as different as we like so long as nothing on the outside notices.

## The one rule

irrd-ng is a drop-in replacement for IRRd 4.5.4. An operator should be able to stop `irrd`, run a one-shot import, start `irrd-ng` with the same `irrd.yaml`, and no client should notice. Same whois responses byte for byte, same HTTP and GraphQL, same NRTM, same mails, same CLI tools with the same exit codes.

That rule drives almost every decision below. When there was a choice between "nicer" and "identical to v4", identical won, every time. Speed and memory come second. They matter a lot, they're half the reason this project exists, but an optimisation that changes one byte of output is a regression, not a feature.

## What v4 looks like, and why we didn't copy the shape

v4 is a solid piece of software and we lean on it heavily as the reference. But its architecture is very much "Python service in 2018":

- Python 3, multiple processes. A pool of whois workers, an HTTP server, a mirror runner, a ROA importer, a preload process, each its own process.
- PostgreSQL holds everything: objects, the NRTM journal, ROAs, status, users. 13 tables, 26 alembic migrations.
- Redis sits beside it for two jobs: a preload cache of route data so `!g`/`!6`/`!a` don't hit Postgres for every query, and the pub/sub glue between processes (event stream, reload signals).
- PGP goes through a real `gpg` binary via python-gnupg, with a keyring on disk.

On a production v4 we use as a reference (about 5.4M objects plus 1M ROAs) we measured the cost of that shape on 2026-10-31: the Postgres database was 14 GB before cleanup, and the processes add up to several GB of RSS, with the ROA importer alone at 2.1 GB, the mirror runner at 1.8 GB, whois workers at 1.1 GB and Postgres itself at 2.4 GB. Three services to run, back up, monitor and upgrade, for what is fundamentally a read-mostly database of a few GB of text.

So the question we asked was: what's the smallest thing that can behave exactly like that?

## The shape we went with

One static binary, one process, one embedded database.

- **One binary.** `irrd-ng` is a multicall binary. It looks at the name it was run as (`irrd`, `irrd_load_database`, `irrdctl`, all 12 of v4's console scripts) and becomes that tool. Symlinks give you the familiar names. `irrd-ng <tool> ...` works too.
- **One process.** A tokio runtime does the network I/O (whois, HTTP, NRTM). There's no worker pool to size and no inter-process plumbing.
- **No Postgres, no Redis.** Storage is LMDB (via `heed`) embedded in the process. Event stream fan-out and reload signals are in-process channels. `database_url` and `redis_url` are still *required* in `irrd.yaml`, because v4 requires them and we validate the file the same way, but we ignore them and log one notice at startup saying so.
- **Static musl builds** for x86_64 and aarch64 are the primary artefacts, with glibc builds alongside. No runtime dependencies at all, which is a big part of why the PGP and Postgres client choices below look the way they do.
- **mimalloc** is the global allocator. musl's malloc is fine for small tools and genuinely slow for this kind of workload, and we didn't want the static build to be the slow one.

## Why LMDB

The workload is very lopsided. Thousands of queries for every write, writes arrive in batches (a mirror update, a ROA refresh, a submission), and queries mostly want small bits of a large dataset by key or by prefix.

LMDB fits that almost too well:

- Readers are lock-free and never block on a writer. A whois query opens a read transaction and sees a consistent snapshot, even while a 1M-object mirror reload is running. In v4 that guarantee comes from Postgres MVCC; here it comes from LMDB's copy-on-write B-trees.
- Data is memory-mapped, so a hot dataset lives in the OS page cache and reads are basically pointer chasing. No serialisation, no socket, no SQL planner. This is also why we dropped v4's Redis preload entirely. The plan is that `!g`, `!6`, `!a` and `!i` are answered straight from secondary indexes. If the load bench shows a hot spot we may add a small in-process cache, but only with RSS numbers before and after.
- One writer at a time. That sounds like a limitation, but v4 effectively serialises writes per source anyway, and it means the journal, object rows, ROA state and status all commit in one atomic transaction. NRTM serials can't get out of step with the objects they describe.

The costs are real and we've tried to be honest about them:

- **One writer.** All writes go through a dedicated writer thread fed by a channel. Big jobs are batched into large transactions, and we never hold a write transaction across an await or network I/O. Get that wrong and every other writer queues behind it.
- **Map size.** LMDB needs a maximum size up front. The store grows the map automatically with headroom and will surface it in `/v1/status/`.
- **Long read transactions pin pages.** Anything long-lived (the event stream, NRTM serving) has to renew its read transaction or the file just keeps growing.
- **Size on disk.** Currently about 1.7 KB per object, so the reference server's copy is about 9.2 GB as a store against 6.4 GB as a freshly restored Postgres. Most of that is the `objects` table (about 750 bytes per object, verbatim text plus parsed fields) and the lookup index (about 300). There's room to compress, but it needs a schema bump, so it waits until the Phase 3 query indexes settle and we can measure with the bench rather than guess.

## The store

The tables deliberately mirror v4's: `rpsl_objects`, `rpsl_database_journal`, `database_status`, `roa_object`, `rpsl_objects_suspended`, `protected_rpsl_name`, `setting`, the web UI auth tables and `change_log`, with fields named after v4's columns. That was a conscious choice. It makes the v4 import a near one-to-one mapping, it means the canonical JSONL export of our store and of v4's Postgres can be diffed line by line, and it means anyone who knows v4's schema can find their way around.

On top of that sit the secondary indexes v4 gets from Postgres indexes and Redis: a case-folded primary key index, v4's lookup fields (for `-i`), set members, an origin index for `!g`/`!6`/`!a`, and IPv4/IPv6/ASN range indexes for exact, less-specific and more-specific lookups. There's a brute-force test that checks every index answers the same as v4's SQL predicate would.

The object text is stored verbatim, next to the parsed fields. RPSL normalisation, continuation lines, case folding and comments all differ between keys, stored text and responses, and the safest way to get output byte-identical is to never regenerate text we already have.

A few store behaviours worth knowing about:

- **Bulk loads skip per-commit fsync.** A full reload or a v4 import opens LMDB without sync and syncs once at the end. On disk, NTTCOM went from 112 s to 33.5 s with that alone. To make it safe there's a durable marker: a per-source marker for `irrd_load_database`, and a whole-store marker for the import. If the process dies cleanly the marker is cleared. If the box actually crashes, a leftover per-source marker sets that source's `force_reload` (v4's own "this needs a full reload" flag) and everything else keeps serving, while a leftover whole-store marker refuses to open, because a half-imported store must never be served.
- **Incremental writes stay durable.** `irrd_update_database`, NRTM and submissions commit with sync, exactly as you'd expect.
- **Insertion order matters more than it should.** Objects are keyed by an internal id assigned on insert, and key-order scans look up each id. Load in random order and a scan of a store bigger than RAM turns into random reads. We found this the hard way on a slow VM disk (an export of the reference copy took 1,075 s). The importer now reads Postgres in the store's key order, which got full RADB from 357 s to 104 s and the export down to 17 s. `irrd_load_database` still inserts in file order, and fixing that properly is on the Phase 3 list.
- **We copy v4's quirks here too.** For example v4's upsert resets `created` on every update, because its `ON CONFLICT DO UPDATE` sets every column from the incoming row including the default. We do the same.

## Getting into irrd-ng from v4

`irrd-ng import --from-postgres <dsn>` is a one-shot, read-only migration from a v4 4.5.x database. It checks the alembic revision first and refuses anything that isn't 4.5. It reads inside a read-only, repeatable-read transaction so it sees one consistent snapshot, streams in batches so memory stays bounded, and writes with the same upsert semantics, so running it twice changes nothing.

The important property is that **NRTM serials survive unchanged**. If they didn't, every downstream mirror would need a full reload on cutover, and that's the kind of thing that makes an operator not switch.

The Postgres client is pure Rust (with rustls if TLS is needed), so it works in the static musl build.

## Parsing: porting Python's behaviour, not just the logic

This was the part that surprised us most. Reproducing v4's output isn't just reproducing v4's code. A lot of what an operator sees comes from the libraries v4 sits on, and those have their own opinions:

- **YAML.** No serde YAML crate matches PyYAML's YAML 1.1 typing (`yes`/`on` as booleans, `010` as octal, sexagesimal numbers, timestamps, merge keys, last-wins duplicates) or its error messages and line/column positions, which v4 shows operators when their config is broken. So the config crate has a line-by-line port of PyYAML's safe loader.
- **Python's own text.** Startup errors embed the Python `repr()` of the error list, so we have a port of `repr()` for strings and floats, checked against CPython 3.13 from the v4 image.
- **IPy, `limits`, `urlparse`, CPython's `int()` and `strptime`, passlib's bcrypt checks.** All ported where v4's output depends on them.
- **Unicode tables** (case mapping, whitespace, printable, digits) are generated from the v4 container's own Python, so we don't drift just because Rust ships a different Unicode version.

It's more work than "write a nice parser", but it's the only way to get identical error text, and identical error text is part of the contract.

We even reproduce v4's bugs. Two message bugs we fixed on purpose (DIV-001 and DIV-002 in `docs/divergences.md`). Everything else stays. The comment-stripping precedence in `split_paragraphs_rpsl` looks like a bug, but we traced every caller and the behaviour it produces is actually the right one for NRTMv3 streams, so we kept it and wrote it out explicitly.

## PGP without gpg

v4 shells out to `gpg` through python-gnupg. We use sequoia-openpgp with its pure-Rust crypto backend instead, mostly so the static build has no C dependencies and doesn't need a gpg binary and keyring directory around.

The catch is that `fingerprint`, `owner` and `method` on key-cert objects come out of gpg's import, so they have to match gpg exactly. That meant testing gpg 2.4.7 directly and reproducing its behaviour: the armour header lost to RPSL normalisation, CRC and END-line rules, user IDs without a valid self-signature being dropped, the primary user ID moving to the front, and the Latin-1 mangling of non-ASCII names in `owner` ("BÃ¶ing"). Every key-cert in the cached dumps matches.

Two costs to be aware of: sequoia is LGPL-2.0-or-later, which has relinking implications for a static binary and is part of the open licence decision. And we accept two upstream timing advisories (in `rsa` and `crypto-bigint`) because they affect private-key operations and we only ever verify public signatures.

## Config

Same `irrd.yaml`, same keys, same defaults, same validation errors in the same order, same unknown-key handling, same environment overrides (`IRRD_<KEY>`), same SIGHUP behaviour. Every setting carries whether it takes effect on restart, on SIGHUP, or on next use, copied from v4.

The one thing irrd-ng needs that v4 doesn't is somewhere to put the store. We didn't want to invent an `irrd.yaml` key, because then a v4 config wouldn't be a valid irrd-ng config (or worse, v4 would choke on an irrd-ng one). So it's an environment variable, `IRRD_NG_STORE_PATH`, defaulting to `/var/lib/irrd-ng`. It's listed as a proposed divergence.

## How we know it matches

We don't trust ourselves to read v4 correctly, so most of the testing asks v4 directly:

- **Oracles.** Small Python scripts run inside the pinned v4 image (built from the 4.5.4 tag, pinned by commit and base image digests) and record what v4 itself does with an input: how it splits a file, what each object parses to, which messages it produces, how it renders, what it says about a config file. irrd-ng is diffed against that. The RPSL oracle covers every paragraph of the cached registry dumps, 4,466,948 of them across AFRINIC, ALTDB, APNIC, ARIN, LACNIC, NTTCOM, RADB and RIPE-NONAUTH, and they all match in both strict and non-strict mode.
- **Fixtures, not committed data.** CI cuts a deterministic sample (about 25k objects) out of cached public dumps every run. Real registry data never goes into git.
- **Fuzzing against v4.** The config crate was fuzzed with about 21k YAML documents and 43k configurations, each run through v4 as well.
- **The three-way load check.** Each dump is loaded into v4 with v4's loader, into irrd-ng with irrd-ng's loader, and into irrd-ng again by importing v4's Postgres. All three are exported in one canonical JSONL format and diffed. The loader and the importer test each other, and both are tested against v4.
- **A real database.** A read-only copy of the production reference server (taken with `pg_dump`, restored on a separate VM, never written back) is the full-scale test for the importer and, from Phase 3, the load bench. Production auth data in it never leaves that VM.
- **The rule.** A failing diff gets fixed in the code or gets a reviewed entry in `docs/divergences.md`. We never edit the expected output to make a test go green.

## Things that are knowingly different

Beyond the behaviour divergences, a few structural ones are worth calling out:

- **Standby.** v4 standbys are Postgres streaming replicas. LMDB has no equivalent, so irrd-ng will replicate natively: the standby follows the active over an authenticated stream of the store's own change log, and `readonly_standby: true` keeps its v4 meaning. That's Phase 9 and needs one new key, which will be a listed divergence.
- **Crashes become errors.** Where a bad input makes v4 die with a Python traceback, irrd-ng reports the same exception as a normal error and, on SIGHUP, keeps running with the old config.
- **Stable ordering where v4's is random.** v4 sometimes builds output from Python sets, which come out in a different order every run. We can't match a random order, so we use a fixed one (file order, or key order).

## What's still open

- Object id locality for `irrd_load_database` and the store's size per object, both decided with the Phase 3 bench.
- Where the PGP keyring lives (the plan is a store table filled from key-cert imports, Phase 7).
- The licence, before any public release.
- The proposed divergences in `docs/divergences.md` waiting for review.

The performance story isn't written yet on purpose. We expect queries to be a lot faster than v4, for the structural reasons above, but the rule for this project is that performance claims come with numbers from the load bench against v4 on the same data, and that bench lands in Phase 3.
