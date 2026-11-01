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
- **Map size.** LMDB needs a maximum size up front. The store grows the map automatically with headroom Showing it in `/v1/status/` would change v4's status text, so it waits on a decision (P-39). Growing it means remapping, which LMDB only allows while no transaction is open in the process, so a resize waits for the readers of the moment. Queries take milliseconds, so that wait is short. Reads that can take minutes (a standby snapshot, an export, the event stream's initial download, an NRTMv4 snapshot) register as long readers: a resize that needs one of them to finish waits for it without holding back queries, so only the write that wanted the space waits. A standby snapshot also grows the map before it starts, by as much as the store already uses, so that waiting is unlikely in the first place.
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

`irrd` serves whois on `server.whois.interface`/`port` and HTTP (`/v1/whois/`, `/v1/status/`, `/graphql/`, `/metrics/` and the event stream) on `server.http.interface`/`port`. v4's environment overrides work for any setting, e.g. `IRRD_SERVER_WHOIS_PORT=8043`, which is the easy way to run it beside a v4 on the same host. The HTTP server applies v4's trusted-host check against `server.http.url`, so clients must send a matching `Host`.

`irrd` starts the way v4's `irrd/daemon/main.py` does. Without `--foreground` it insists on `log.logfile_path` or `log.logging_config_path`, checks the log file is writable by the configured user, and detaches: the command returns at once with exit status 0, and the daemon carries on in a session of its own with no terminal. python-daemon forks twice to get there; irrd-ng starts itself again instead, because forking a process that may already have threads is not safe in Rust. Both then do what python-daemon's `DaemonContext` does: no core dumps, umask 022, working directory `/`. That last one matters because the configuration file is read again after it, as in v4, so relative paths in `irrd.yaml` (and a relative `--config`) resolve from `/` exactly as they do for v4. `IRRD_NG_STORE_PATH` is resolved before the change, since it is irrd-ng's own.

The PID file is v4's: `irrd.pid` in `piddir`, created, locked with `flock` and written the way the `pid` library v4 uses does, with the same messages when another instance holds it or the file names a running process, and removed on exit. Run as root, the daemon requires `user` and `group` (unless `CI` is set, as in v4), binds the whois port as root, and then switches to that user before it opens the store or binds the HTTP port, which v4 also binds as the unprivileged user. One difference: python-daemon's switch only calls `initgroups()`, which leaves v4 running with root as its primary group; irrd-ng also sets the configured group.

SIGHUP re-reads and re-checks `irrd.yaml` and logs v4's messages. A valid file takes effect the way it does in v4's code, which is not always what v4's documentation says: settings v4 reads at each use (most of them, including `download_timeout` and the status page's view of `server.whois.interface`) change at once, while the ones its processes only read at startup (listening addresses and ports, `server.whois.max_connections`, `server.http.forwarded_allowed_ips`, `piddir`, `user`, `group`, the log destination) keep their startup values until a restart. The root log level follows `log.level` on every reload, as `_commit_staging()` sets it. SIGTERM stops the scheduler's runners, closes the listeners and logs v4's shutdown lines, ending with `Main process exiting`.

Logging is a small model of Python's `logging` rather than a stock Rust logger, because operators' log processing depends on it. The default is v4's: the `verbose` format to stderr, or to `log.logfile_path` through `WatchedFileHandler` semantics, so the file is reopened when log rotation moves it. `log.logging_config_path` names a Python file whose `LOGGING` dictionary v4 hands to `dictConfig()`. irrd-ng reads that file as data, not code: module-level assignments of literals, `dict(...)`, string concatenation, names defined earlier and the `logging` level constants, with imports skipped. From the dictionary it builds formatters (`%`-style formats and `datefmt`), handlers (stream, file, watched file, syslog over a Unix socket or UDP, null) and loggers with levels, handlers and propagation, and applies them with Python's hierarchy rules. Anything it cannot reproduce (filters, custom classes, rotating handlers that rotate themselves, `disable_existing_loggers`) is named in a warning at startup and left out.

Whois connections are served like v4's fixed worker pool: every connection is accepted and waits for one of `server.whois.max_connections` slots, rather than being refused. A panic while answering a query is contained to that query: it is logged with the query, and the client gets v4's internal error, exactly as if v4's code had raised an exception there.

## The HTTP API

v4's HTTP side is Starlette behind uvicorn, with GraphQL through ariadne and graphql-core. irrd-ng serves the same routes from hyper, with the middleware behaviour copied: the trusted host check, slash redirects, 405s with their `allow` headers, uvicorn's proxy headers and `server` header, and IRRd's security headers in their order.

GraphQL was the part where "copy the behaviour" meant porting a library. Clients see graphql-core's messages verbatim: syntax errors, every validation rule's text and the order rules report in, coercion errors with Python's `repr()` of the value, and the JSON shape of each error. No Rust GraphQL crate produces those, so the `graphql` crate is a port of the parts of graphql-core 3.3 and ariadne 1.1 that IRRd uses: the lexer and parser, the schema built from v4's SDL in graphql-core's type map order (introspection shows it), all specified validation rules run as graphql-core runs them (a parallel visitor over a `TypeInfo`), ariadne's cost validator, the executor with null propagation, and introspection. It knows nothing about IRRd; the resolvers live in the `http` crate.

Porting it this closely brought v4's quirks along, and they stay:

- ariadne's cost validator computes field arguments without the request's variables. A variable in a required argument (`recursiveSetMembers(setNames: $names)`) therefore fails validation in v4 with `Invalid argument` and a printed source location. irrd-ng answers the same.
- IRRd's error formatter replaces the message of any error that wraps a non-GraphQL exception with `Internal server error`, which covers a resolver's `ValueError` ("Your query must be more specific."), unknown sources, non-null violations and some coercion failures.
- graphql-core places an error that starts a line at the end of the previous one, because it counts lines with `str.splitlines()`.

Two other ways into `/graphql/` are copied for what v4 actually does with them, which is never to return a result. v4 mounts ariadne's default WebSocket handler, the legacy `graphql-ws` protocol of subscriptions-transport-ws: it accepts with the `graphql-ws` subprotocol whatever the client offers, answers each `connection_init` with `connection_ack`, closes with 4401 on a `start` before that, ignores `stop` and unknown types, closes normally on `connection_terminate`, and sends an `error` message for a syntax error or a subscription (the schema has none, so the first validation error). A query or mutation is handed to the HTTP handler, where IRRd's `QueryMetadataExtension` reads `request._json`, which a WebSocket does not have, so the connection drops without a close frame; irrd-ng drops it the same way without running the query. Anything `receive_json()` cannot take (binary frames, invalid JSON, a non-object) drops it too. A multipart request (the GraphQL multipart request spec) goes through Starlette's form parser, python-multipart's parser and `email.message` parameter parsing, ported in `http::multipart`, so the same malformed requests get the same 400 texts; one that gets as far as execution is a 500 in v4 for the same `request._json` reason, and in irrd-ng.

WebSocket upgrades are answered before hyper sees the connection, so the 101 and the refusals keep the header case of uvicorn and websockets: the handshake is checked first, then `/v1/event-stream/` and the `/graphql` mount are accepted, the mounts of HTTP endpoints get uvicorn's bare 500, and every other path websockets' 403. A client's close frame is answered as websockets answers it: the same code and reason, nothing for an empty frame, 1002 for a bad code and 1007 for a reason that is not UTF-8.

`rpslObjects` runs any combination of filters through a port of `RPSLDatabaseQuery` over the store's indexes (`query::objects`). v4 runs these queries without `ORDER BY`, so its row order is whatever PostgreSQL's plan gives; irrd-ng returns rows in internal id order. `sqlTrace` reports the SQL v4 would have run, rendered as SQLAlchemy would, since there is no SQL to report.

`/v1/status/` and `/metrics/` are generated from the store as v4 generates them from PostgreSQL, the status table formatted the way BeautifulTable 0.8 formats it. Object counts come from the key index alone, so they never touch object data.

The event stream replaces Redis with an in-process stream with Redis-style ids. The store publishes `journal_extended` after each commit that added journal entries and the mirror runner publishes `full_reload`; a watcher notices journal growth from other processes (the command line tools write the store directly) within two seconds. Followers open a short read transaction for each journal poll, so a long-lived WebSocket never pins old pages. The WebSocket protocol, `permessage-deflate` included, is implemented directly, and the handshake is answered before hyper sees the connection so the 101 response keeps uvicorn's header case.

## Mirroring

The mirroring client is v4's scheduler and runners with the processes turned into tasks. Every three seconds the scheduler starts an import task for each mirrored source whose `import_timer` has expired and that has no task running, at most one new source per round, in configuration order, exactly as v4's `MirrorScheduler` does. `IRRD_TESTING_FAST_SCHEDULER_OVERRIDE` shortens the timers as it does in v4.

A run makes the same decision v4 makes (NRTMv4 if a notification file URL is set; otherwise a full import when `force_reload` is set, no serial is known yet or NRTMv3 is off; otherwise NRTMv3) and has the same all-or-nothing outcome. v4 does each run in one database transaction and rolls it back on any error, mirror errors recorded on the way included. irrd-ng splits the run instead:

1. **Fetch.** All network I/O first: downloads to temporary files (HTTP and HTTPS through reqwest with rustls, FTP through suppaftp, `file://` read in place), gunzip, SHA-256 checks for NRTMv4 files, the NRTMv3 whois query.
2. **Parse.** Outside any write transaction, on all cores. Large inputs (full imports, NRTMv4 snapshots) are read a block at a time and parsed rows go to a temporary spool file, so memory stays bounded however big the source.
3. **Write.** One write transaction applies everything, from the spool or from the prepared NRTM operations, and the store's `DatabaseStatusTracker` port updates `database_status` (including `rpsl_data_updated`) at commit as v4's does. A failure in steps 1 or 2 writes nothing, as v4's rollback does. Full imports are written in key order, like `irrd_load_database`; NRTMv4 snapshots keep file order, because v4 journals the tail of its upsert buffer after re-enabling journaling and the order decides which objects that is.

The static build never touches libc's resolver: names are resolved by hickory from `/etc/hosts` and `/etc/resolv.conf`, and TLS trusts the Mozilla roots compiled into the binary, the way v4's `requests` trusts certifi's bundle. `REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE` replace the bundle as they do for v4. The differential runs the musl binary in an empty `FROM scratch` image to prove it.

Signatures on NRTMv4 Update Notification Files are ES256 JWS, verified with the pure-Rust `p256` crate; the error texts are joserfc's. pydantic's validation of the notification file and the snapshot and delta headers is reproduced with its error messages, because v4 logs them.

There's one place we deliberately don't follow v4 here. v4's NRTMv4 client keeps the file hashes it has seen across sessions, and file names like `snapshot-1` get reused when a server resets its session, so after a reset v4 decides the server is rewriting history and stays stuck on every run until someone edits the database by hand. irrd-ng only compares hashes within one session, so it reloads from the new snapshot and carries on. That's DIV-003, and the mirroring side-by-side checks both halves of it: v4 still gets stuck, and irrd-ng ends up identical to the upstream.

## Serving data

irrd-ng serves its data to other IRR servers the three ways v4 does, and a v4 mirror can't tell which of the two it is following.

- **NRTMv3** (`-g` on the whois port) is answered straight from the journal table by the query engine, with v4's checks in v4's order: access lists, `keep_journal`, the serial range, `nrtm_query_serial_range_limit` and `nrtm_query_serial_days_limit`, then the optional `nrtm_response_header`. Clients in `nrtm_access_list_unfiltered` get the objects as stored; everyone else gets password hashes removed and the `nrtm_dummified_*` attributes replaced.
- **Exports** (`export_destination`, `export_destination_unfiltered`, `export_timer`) are written the way v4's `SourceExportRunner` writes them: a gzipped dump in v4's object order without suppressed objects, then `# EOF`, written to a temporary file and moved into place, plus the `CURRENTSERIAL` file.
- **NRTMv4** is v4's `NRTM4ServerWriter`: snapshots, deltas and a signed Update Notification File in `nrtm4_server_local_path`, for a web server to publish. Like v4, irrd-ng has no HTTP route for these files. Sessions, key rotation with `nrtm4_server_private_key_next`, the snapshot frequency, the integrity check and the 24-hour expiry of deltas and dangling snapshots all follow v4. The two lock files v4 keeps in `piddir` are in-process locks, since every server runs in the one process.

Exports and NRTMv4 files are byte-identical to v4's, apart from the gzip header's time and file name fields, which v4 itself never writes the same way twice. Getting there took one deliberate dependency choice: the deflate stream depends on the compressor, and neither pure-Rust implementation (miniz_oxide, zlib-rs) produces the bytes CPython's zlib does. irrd-ng links the reference zlib 1.3.1, built from source and linked statically, which also keeps the musl build static. The JSON in NRTMv4 files is written the way ujson writes it (every `/` escaped, non-ASCII as `\u` escapes), and the Update Notification File the way pydantic writes it.

There is one place where irrd-ng is more consistent than v4 rather than identical. v4 reads the newest journal serial, the delta's entries and the snapshot's objects in one READ COMMITTED transaction, so a change committed during a run can land in a snapshot and be sent again in the next delta. irrd-ng reads all three from one LMDB snapshot. The files are the same whenever nothing is written during a run, which is what the differential checks.

The serving differential, `parity/mirror/serve.sh`, runs a v4 upstream and an irrd-ng upstream side by side, feeds both the same changes, and has a v4 mirror follow each one. After every step it compares the two mirrors, the two upstreams, the exports byte for byte, what the two NRTMv4 repositories serve, and the NRTMv3 answers from `parity/corpus/whois/nrtm.q`.

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

## The keyring

v4's keyring is a GnuPG home directory: every key-cert parsed in strict mode imports its key, whether the change that carried it is saved or not, and nothing ever removes one. irrd-ng keeps the keyring in the store's `pgp_keyring` table (schema version 4). Each entry holds what gpg's import kept (user IDs with their self-signature times, subkeys, signatures), which `owner` is derived from, plus the public key packets. A mirror run, `irrd_load_database`, `irrd_update_database` and `irrd_load_pgp_keys` load it, and write the keys they imported back in a transaction of their own, so like v4's they stay even when the run rolls back. A submission writes them in its own transaction. Signed e-mail (inline and PGP/MIME) is checked against it with sequoia, the way `gpg --verify` would: a good signature by a key that is not expired or revoked now.

The v4 import cannot copy a GnuPG keyring, so it rebuilds one from every key-cert in the store, and PGP signed submissions keep working after the migration as they did on v4. `--no-load-pgp-keys` leaves the keyring empty, as on a v4 moved to a new host, and `irrd_load_pgp_keys` then fills it per source.

## Submissions

`irrd/updates` is ported in the `auth` crate. A submission (an e-mail from `irrd_submit_email`, `/v1/submit/`, `/v1/suspension/`) runs in one store write transaction, as v4 runs it in one database transaction: parsing, the rounds of validation that resolve references between objects of the same submission, the saves and the change log. Reports and notification mails are built afterwards from the result. Python's own behaviour shows up in the replies, so the e-mail parser is a port of the parts of Python's `email` package v4 relies on (compat32 headers, `get_payload(decode=True)` including its raw-unicode-escape fallback for 8 bit bodies), the request bodies go through a port of `json.loads` and pydantic's error texts, and the change diff in notifications is `difflib.unified_diff`.

`parity/submit/run.sh` is the mutation suite: v4 and irrd-ng from the same data, the same e-mails, HTTP requests and CLI runs, and a comparison of responses, mails, the NRTMv3 journal and the canonical exports.

## Config

Same `irrd.yaml`, same keys, same defaults, same validation errors in the same order, same unknown-key handling, same environment overrides (`IRRD_<KEY>`), same SIGHUP behaviour. Every setting carries whether it takes effect on restart, on SIGHUP, or on next use, copied from v4.

The one thing irrd-ng needs that v4 doesn't is somewhere to put the store. We didn't want to invent an `irrd.yaml` key, because then a v4 config wouldn't be a valid irrd-ng config (or worse, v4 would choke on an irrd-ng one). So it's an environment variable, `IRRD_NG_STORE_PATH`, defaulting to `/var/lib/irrd-ng`. It's listed as P-18 in `docs/divergences.md`.

Standby replication is the one place a key could not be avoided, because both ends need the same secret and the standby needs to know where the active is. It is a single top-level mapping, `ng_replication`, with `secret`, `interface` and `port` on the active and `active_host` and `active_port` on a standby, plus optional TLS settings: `tls_certificate` and `tls_key` on the active, `tls_ca` or `tls_pin` and an optional `tls_server_name` on a standby. It is checked after every check v4 makes, so a v4-valid file gets exactly v4's result, and a file that uses it is one v4 would refuse. The secret can come from the environment (`IRRD_NG_REPLICATION_SECRET`), as any setting can.

## How we know it matches

We don't trust ourselves to read v4 correctly, so most of the testing asks v4 directly:

- **Oracles.** Small Python scripts run inside the pinned v4 image (built from the 4.5.4 tag, pinned by commit and base image digests) and record what v4 itself does with an input: how it splits a file, what each object parses to, which messages it produces, how it renders, what it says about a config file. irrd-ng is diffed against that. The RPSL oracle covers every paragraph of the cached registry dumps, 4,466,948 of them across AFRINIC, ALTDB, APNIC, ARIN, LACNIC, NTTCOM, RADB and RIPE-NONAUTH, and they all match in both strict and non-strict mode.
- **Fixtures, not committed data.** CI cuts a deterministic sample (about 25k objects) out of cached public dumps every run. Real registry data never goes into git.
- **Fuzzing against v4.** The config crate was fuzzed with about 21k YAML documents and 43k configurations, each run through v4 as well.
- **Fuzzing for crashes.** `fuzz/` holds cargo-fuzz targets (nightly only; the main build stays on the pinned stable toolchain) for every parser that reads outside input: RPSL, whois queries, e-mail, multipart and JSON request bodies, GraphQL, WebSocket frames, NRTMv3 streams, NRTMv4 files, ROA and SLURM files, `irrd.yaml` and replication frames. `fuzz/make_seeds.py` seeds them from the parity corpus. Every input that ever crashed one is kept as a unit test next to the code it broke.
- **The three-way load check.** Each dump is loaded into v4 with v4's loader, into irrd-ng with irrd-ng's loader, and into irrd-ng again by importing v4's Postgres. All three are exported in one canonical JSONL format and diffed. The loader and the importer test each other, and both are tested against v4.
- **A real database.** A read-only copy of the production reference server (taken with `pg_dump`, restored on a separate VM, never written back) is the full-scale test for the importer and, from Phase 3, the load bench. Production auth data in it never leaves that VM.
- **The rule.** A failing diff gets fixed in the code or gets a reviewed entry in `docs/divergences.md`. We never edit the expected output to make a test go green.

## Standby

v4 runs a standby as a PostgreSQL streaming replica with `readonly_standby: true`. irrd-ng has no PostgreSQL to stream, so it replicates its own store.

When an active is configured to serve standbys (`ng_replication.port`), its store keeps a replication log: every write transaction appends one entry, in the same LMDB transaction, listing the row changes it made to every table. That includes the indexes, the journal, `database_status`, ROAs, suspensions, settings, the web UI tables and the keyring, and it includes writes by the command line tools, because the changes are captured underneath the write API, in the table layer every write goes through. A transaction that writes more than 64 MiB, and anything written in bulk-load mode (the v4 import, `irrd_load_database`), logs a resync marker instead of its rows. Entries are kept for 24 hours. A few `meta` keys are local to each store and never replicated: the schema version, the map size history, bulk-load markers and the replication bookkeeping itself.

A standby (`readonly_standby: true` plus `ng_replication.active_host` and `active_port`) connects to the active and follows the log. The handshake proves both ends hold the shared secret without sending it (HMAC-SHA256 over a nonce from each side) and derives a session key, and every frame after it carries a tag under that key with a frame counter, so nothing can be injected or replayed. Before that handshake has proved the secret, neither end accepts a frame over 4 KiB. With `tls_certificate` and `tls_key` set, the active only accepts TLS 1.3 (rustls with the ring provider, so the static musl builds stay free of C), and the whole exchange, handshake included, runs inside it. A standby with `tls_ca` checks the active's certificate against that CA and the host name; with `tls_pin` it accepts exactly the certificate with that SHA-256 fingerprint, which suits a self-signed certificate. Each end insists on its own choice, so a plaintext standby is refused by a TLS active with a message saying why, and a TLS standby never falls back to plaintext. Without TLS the stream is authenticated but not encrypted, and both ends log a warning at startup. A new standby, one that was away longer than the log is kept, or one that reaches a resync marker gets a snapshot first: every replicated row, read from one consistent read transaction on the active, spooled to a file on the standby and applied in one write transaction. That read transaction stays open as long as the standby takes to receive the rows, and LMDB cannot grow the map meanwhile, so the active grows it first (by as much as is in use) and holds the snapshot as a long reader (see Why LMDB): queries carry on throughout, and a write that still needs more room waits for the snapshot to finish rather than stopping the server. After that it applies the log entry by entry, each in a transaction of its own, so readers on the standby see the active's transactions whole. It reconnects with backoff when the stream drops, and carries on from the last entry it applied after a restart.

The standby keeps v4's meaning of `readonly_standby`: the scheduler runs nothing (no mirroring, imports, exports, NRTMv4 files, ROA, scope filter or route preference jobs), the command line tools that write refuse to run, and the store refuses every write except the replication apply. The two-store test in `crates/replication` checks that a standby converges to the same rows as the active in every table, through restarts of either side, a trimmed log and a resync, and that an idle standby commits nothing at all. Promotion is the v4 one: turn `readonly_standby` off and send SIGHUP or restart. The follower stops at that SIGHUP, before anything else may write.

## Things that are knowingly different

Beyond the behaviour divergences, a few structural ones are worth calling out:

- **Standby.** v4 standbys are Postgres streaming replicas. irrd-ng replicates its store natively (see Standby above), which needs one new top-level key, `ng_replication`, that v4 does not know.
- **Crashes become errors.** Where a bad input makes v4 die with a Python traceback, irrd-ng reports the same exception as a normal error and, on SIGHUP, keeps running with the old config.
- **Stable ordering where v4's is random.** v4 sometimes builds output from Python sets, which come out in a different order every run. We can't match a random order, so we use a fixed one (file order, or key order).

## Licence

irrd-ng is LGPL-2.1-or-later (`LICENSE`). It's a reimplementation of v4, and a lot of it is ported straight from v4's code, messages and tests, so v4's BSD-2-Clause notice is kept in `NOTICE` as that licence requires.

## What's still open

- The proposals still waiting for review in `docs/divergences.md`, and the Phase 9 ones (the `ng_replication` key, partial `logging_config_path` support, the primary group after dropping privileges, SIGHUP not restarting HTTP workers).

The performance numbers are in `bench/RESULTS.md`, measured against v4 on the same data with the scripts in `bench/`. They come from the Tier 1 data on a development box; the production-size bench on the Tier 2 VM (`bench/load.sh`) still has to be run again with the Phase 10 changes.
