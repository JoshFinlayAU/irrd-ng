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
- **Size on disk.** About 1.3 to 1.4 KB per object since schema version 2 (full RADB, 1.37M objects: 1,839 MB loaded with `irrd_load_database`, down from 2,050 MB). Most of it is the `objects` table (about 740 bytes per object, verbatim text plus parsed fields). Version 2 shrank the look-up index from 299 to 166 bytes per object: its keys name the attribute by a one-byte code, and attribute presence (`parsed_data ? attr`) is indexed only for `member-of` and `mbrs-by-ref`, the only presence v4 ever asks about; any other presence check scans. Compressing `objects` would cost the zero-copy reads the query path relies on, so it stays as it is.

## The store

The tables deliberately mirror v4's: `rpsl_objects`, `rpsl_database_journal`, `database_status`, `roa_object`, `rpsl_objects_suspended`, `protected_rpsl_name`, `setting`, the web UI auth tables and `change_log`, with fields named after v4's columns. That was a conscious choice. It makes the v4 import a near one-to-one mapping, it means the canonical JSONL export of our store and of v4's Postgres can be diffed line by line, and it means anyone who knows v4's schema can find their way around.

On top of that sit the secondary indexes v4 gets from Postgres indexes and Redis: a case-folded primary key index, v4's lookup fields (for `-i`), set members, an origin index for `!g`/`!6`/`!a`, and IPv4/IPv6/ASN range indexes for exact, less-specific and more-specific lookups. There's a brute-force test that checks every index answers the same as v4's SQL predicate would.

The object text is stored verbatim, next to the parsed fields. RPSL normalisation, continuation lines, case folding and comments all differ between keys, stored text and responses, and the safest way to get output byte-identical is to never regenerate text we already have.

A few store behaviours worth knowing about:

- **Bulk loads skip per-commit fsync.** A full reload or a v4 import opens LMDB without sync and syncs once at the end. On disk, NTTCOM went from 112 s to 33.5 s with that alone. To make it safe there's a durable marker: a per-source marker for `irrd_load_database`, and a whole-store marker for the import. If the process dies cleanly the marker is cleared. If the box actually crashes, a leftover per-source marker sets that source's `force_reload` (v4's own "this needs a full reload" flag) and everything else keeps serving, while a leftover whole-store marker refuses to open, because a half-imported store must never be served.
- **Incremental writes stay durable.** `irrd_update_database`, NRTM and submissions commit with sync, exactly as you'd expect.
- **Insertion order matters.** Objects are keyed by an internal id assigned on insert, and key-order scans look up each id. Load in random order and a scan of a store bigger than RAM turns into random reads. We found this the hard way on a slow VM disk (an export of the reference copy took 1,075 s). The importer reads Postgres in the store's key order (full RADB from 357 s to 104 s, the export down to 17 s), and since Phase 3 `irrd_load_database` parses in file order (every log line, error and counter as v4 has them) and then writes in key order, so its ids follow key order too. That also made the load itself faster, because the index inserts land in order (full RADB: 40 to 48 s down to 35 s, peak RSS 2.55 to 2.48 GB on the dev box). Incremental writes (NRTM, submissions) still get the next id, which is fine at their volume.
- **IPv6 inside `::/96` has an IPv4 `ip_last`.** v4 stores `str(IP.broadcast())`, and IPy guesses the version of the broadcast address from its integer value, so `route6: ::/104` is stored with `ip_last` `0.255.255.255`. PostgreSQL then compares it as IPv4, which sorts below every IPv6 address. irrd-ng stores the same values, indexes such rows by their integer range (schema version 3), and applies v4's family-aware comparisons in queries, so `!r`, `-x/-l/-L/-M` and free-text searches there give v4's answers.
- **We copy v4's quirks here too.** For example v4's upsert resets `created` on every update, because its `ON CONFLICT DO UPDATE` sets every column from the incoming row including the default. We do the same.

## Running it

irrd-ng reads the same `irrd.yaml` as v4. The store's directory is the one thing v4's file has no key for, so it comes from the environment:

```sh
export IRRD_NG_STORE_PATH=/var/lib/irrd-ng           # the default
irrd-ng irrd_load_database --config irrd.yaml --source RADB radb.db   # or: irrd-ng import --from-postgres <dsn>
irrd-ng irrd --config irrd.yaml --foreground
```

`irrd` serves whois on `server.whois.interface`/`port` and HTTP (`/v1/whois/` so far) on `server.http.interface`/`port`. v4's environment overrides work for any setting, e.g. `IRRD_SERVER_WHOIS_PORT=8043`, which is the easy way to run it beside a v4 on the same host. The HTTP server applies v4's trusted-host check against `server.http.url`, so clients must send a matching `Host`.

Whois connections are served like v4's fixed worker pool: every connection is accepted and waits for one of `server.whois.max_connections` slots, rather than being refused. A panic while answering a query is contained to that query: it is logged with the query, and the client gets v4's internal error, exactly as if v4's code had raised an exception there.

## Mirroring

The mirroring client is v4's scheduler and runners with the processes turned into tasks. Every three seconds the scheduler starts an import task for each mirrored source whose `import_timer` has expired and that has no task running, at most one new source per round, in configuration order, exactly as v4's `MirrorScheduler` does. `IRRD_TESTING_FAST_SCHEDULER_OVERRIDE` shortens the timers as it does in v4.

A run makes the same decision v4 makes (NRTMv4 if a notification file URL is set; otherwise a full import when `force_reload` is set, no serial is known yet or NRTMv3 is off; otherwise NRTMv3) and has the same all-or-nothing outcome. v4 does each run in one database transaction and rolls it back on any error, mirror errors recorded on the way included. irrd-ng splits the run instead:

1. **Fetch.** All network I/O first: downloads to temporary files (HTTP and HTTPS through reqwest with rustls, FTP through suppaftp, `file://` read in place), gunzip, SHA-256 checks for NRTMv4 files, the NRTMv3 whois query.
2. **Parse.** Outside any write transaction, on all cores. Large inputs (full imports, NRTMv4 snapshots) are read a block at a time and parsed rows go to a temporary spool file, so memory stays bounded however big the source.
3. **Write.** One write transaction applies everything, from the spool or from the prepared NRTM operations, and the store's `DatabaseStatusTracker` port updates `database_status` (including `rpsl_data_updated`) at commit as v4's does. A failure in steps 1 or 2 writes nothing, as v4's rollback does. Full imports are written in key order, like `irrd_load_database`; NRTMv4 snapshots keep file order, because v4 journals the tail of its upsert buffer after re-enabling journaling and the order decides which objects that is.

The static build never touches libc's resolver: names are resolved by hickory from `/etc/hosts` and `/etc/resolv.conf`, and TLS trusts the Mozilla roots compiled into the binary, the way v4's `requests` trusts certifi's bundle. `REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE` replace the bundle as they do for v4. The differential runs the musl binary in an empty `FROM scratch` image to prove it.

Signatures on NRTMv4 Update Notification Files are ES256 JWS, verified with the pure-Rust `p256` crate; the error texts are joserfc's. pydantic's validation of the notification file and the snapshot and delta headers is reproduced with its error messages, because v4 logs them.

There's one place we deliberately don't follow v4 here. v4's NRTMv4 client keeps the file hashes it has seen across sessions, and file names like `snapshot-1` get reused when a server resets its session, so after a reset v4 decides the server is rewriting history and stays stuck on every run until someone edits the database by hand. irrd-ng only compares hashes within one session, so it reloads from the new snapshot and carries on. That's DIV-003, and the mirroring side-by-side checks both halves of it: v4 still gets stuck, and irrd-ng ends up identical to the upstream.

## RPKI, scope filter and route preference

Every route object carries three statuses, as in v4: RPKI (`valid`, `invalid`, `not_found`), scope filter (`in_scope`, `out_scope_as`, `out_scope_prefix`) and route preference (`visible`, `suppressed`). An object that is invalid, out of scope or suppressed is hidden from queries (unless a `!f` override asks for it), from exports and from mirrors. When a status change makes an object appear or disappear, the journal gets an entry for it, with the origin `rpki_status`, `scope_filter` or `route_preference`, so NRTM mirrors follow along.

The three jobs that recompute statuses are v4's runners, started by the mirroring scheduler on v4's terms:

- **ROA import** (`ROAImportRunner`, every `rpki.roa_import_timer` seconds). The ROA JSON and the optional SLURM file are fetched like any mirror file, parsed with v4's rules and error messages, and turned into ROAs and RPKI pseudo-IRR objects. Then, as in v4, two transactions: the first replaces every ROA and every object of the RPKI source (without journal entries), the second re-validates every route and writes the status changes. Only after that does it mail the contacts of route objects in authoritative sources that just became invalid (`rpki.notify_invalid_enabled`), through the `mail` crate, which renders messages byte for byte as Python's `email` package does.
- **Scope filter** (`ScopeFilterUpdateRunner`), whenever the scope filter settings differ from what the scheduler saw last, which includes the first run after start and any SIGHUP that changed them. Like v4, the update matches rows by RPSL primary key, so every object sharing a key gets the new status.
- **Route preference** (`RoutePreferenceUpdateRunner`, every `route_object_preference.update_timer` seconds) re-evaluates every route. Besides that, the store calls a hook before committing any transaction that touched route objects, which re-evaluates the routes overlapping the changed prefixes (or everything, past 5,000 prefixes), as v4's `pre_commit()` does. That covers mirror imports, NRTM, the loaders and the status jobs themselves. Instead of v4's radix tree, the prefixes are sorted, which lays them out in containment order, and one pass with a stack finds the highest preference among each prefix's ancestors and descendants.

`irrd-ng run-job roa-import|scopefilter|route-preference` runs one of these once, which is how the parity harness steps both servers through the same changes.

v4 keeps some behaviour here that looks like a bug, and irrd-ng keeps it too. A ROA repeated under a second trust anchor gives the same pseudo-IRR object twice, which fails v4's unique constraint: the whole import is rolled back, an error is logged and the previous ROAs stay until the input changes. The scope filter key match above is another.

v4 processes the routes of a status update in whatever order PostgreSQL's table scan returns them, so within one batch the journal entries can come in any order. irrd-ng uses the store's key order. The serials, operations and contents of the entries are the same.

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

Two costs to be aware of: sequoia is LGPL-2.0-or-later, and it ends up inside a static binary. That's fine because irrd-ng itself is LGPL-2.1-or-later and ships its source, so anyone can rebuild it against a modified sequoia, which is what the LGPL asks for. And we accept two upstream timing advisories (in `rsa` and `crypto-bigint`) because they affect private-key operations and we only ever verify public signatures.

## Config

Same `irrd.yaml`, same keys, same defaults, same validation errors in the same order, same unknown-key handling, same environment overrides (`IRRD_<KEY>`), same SIGHUP behaviour. Every setting carries whether it takes effect on restart, on SIGHUP, or on next use, copied from v4.

The one thing irrd-ng needs that v4 doesn't is somewhere to put the store. We didn't want to invent an `irrd.yaml` key, because then a v4 config wouldn't be a valid irrd-ng config (or worse, v4 would choke on an irrd-ng one). So it's an environment variable, `IRRD_NG_STORE_PATH`, defaulting to `/var/lib/irrd-ng`. It's listed as P-18 in `docs/divergences.md`, waiting for review.

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

## Licence

irrd-ng is LGPL-2.1-or-later (`LICENSE`). It's a reimplementation of v4, and a lot of it is ported straight from v4's code, messages and tests, so v4's BSD-2-Clause notice is kept in `NOTICE` as that licence requires.

## What's still open

- Where the PGP keyring lives (the plan is a store table filled from key-cert imports, Phase 7).
- The Phase 2 proposals P-15 to P-20 in `docs/divergences.md`, waiting for review.

The performance story isn't written yet on purpose. We expect queries to be a lot faster than v4, for the structural reasons above, but the rule for this project is that performance claims come with numbers from the load bench against v4 on the same data, and that bench lands in Phase 3.
