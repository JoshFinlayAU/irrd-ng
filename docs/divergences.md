# Divergences from IRRd v4

irrd-ng matches IRRd 4.5.4 byte for byte on every surface listed under "The compatibility promise" in the README. This file is the complete list of places where it deliberately does not. Anything that differs from v4 and is not listed here is a bug.

The file has four parts. The DIV entries are deliberate fixes and additions that anyone can see. The accepted minor divergences (P-01 to P-20) are corner cases that were reviewed and accepted. The proposed ones (P-21 onwards) are corner cases still waiting for that review. Each entry says what v4 does, what irrd-ng does instead, who can see the difference, and why. Entries are added only after review, never to make a failing parity diff pass.

## DIV-001: NRTMv4 keep_journal configuration error is formatted

- **v4** (`irrd/conf/__init__.py:477`): the string is missing its `f` prefix and repeats a word, so operators see `NRTMv4 server requires keep_journal to be set for for source {name}.` with a literal `{name}`.
- **irrd-ng**: `NRTMv4 server requires keep_journal to be set for source EXAMPLE.` with the real source name.
- **Visible to**: operators, in the configuration error list at startup or on SIGHUP. Not visible to clients.
- **Why**: a plain bug in v4. The fixed text names the source that needs fixing.

## DIV-002: RPKI notify_invalid configuration error has its missing space

- **v4** (`irrd/conf/__init__.py:558`): two concatenated string literals with no space between them produce `...Set to true or false.DANGER: care is required...`.
- **irrd-ng**: `...Set to true or false. DANGER: care is required...`.
- **Visible to**: operators, in the configuration error list. Not visible to clients.
- **Why**: a plain bug in v4.

## DIV-003: NRTMv4 client follows a server session reset

- **v4** (`irrd/mirroring/nrtm4/nrtm4_client.py:262`): `previous_file_hashes` is kept across sessions and checked against every new Update Notification File. File references such as `snapshot-1` and `delta-2` are only unique within a session, so after the server resets its session the new files collide with the old entries. The client loads the new snapshot, fails the history check with `Server is rewriting history`, rolls the run back, and does the same on every run after that. No v4 tool clears the stored hashes, so the mirror stays stuck until an operator edits `database_status` by hand.
- **irrd-ng**: hashes stored under an earlier session are not compared. On a session change the client logs `Session ID has changed`, reloads from the new snapshot as v4 intends, and starts a fresh set of hashes for the new session. Within one session the history check is unchanged, with the same error text.
- **Visible to**: operators of NRTMv4 mirrors, and their downstream users, after an upstream session reset. Nothing changes until a reset happens.
- **Why**: a plain bug in v4. A reset is part of the NRTMv4 protocol and the client is meant to recover from it. `parity/mirror/run.sh` step 11 checks that v4 still gets stuck and irrd-ng ends up identical to the upstream.

## DIV-004: ROA import ignores repeated ROAs

- **v4** (`irrd/rpki/importer.py`, `ROA.save()`): every ROA gets a pseudo-IRR `route` or `route6` object keyed on prefix, origin and max length, inserted with `rpsl_guaranteed_no_existing`. When the same prefix, origin and max length appear twice, under the same trust anchor or under two different ones, the second insert hits `rpsl_objects_rpsl_pk_source_class_unique`. The whole import rolls back, the error is logged, the runner still exits normally, and the previous ROAs stay in place. Validators publish the same ROA from more than one trust anchor often enough that this happens in practice, and it repeats on every run until the source data changes, so RPKI state silently stops updating.
- **irrd-ng**: an exact repeat (same prefix, origin, max length and trust anchor) is stored once. A repeat under another trust anchor is stored in `roa_object` as its own row, as v4's table allows, but only the first one gets a pseudo-IRR object, so the object's `source:` comment names the first trust anchor in file order. The import then completes as it would have without the repeats. A warning `Ignored N duplicate ROA(s): ...` is logged, with one debug line per repeat. Validation results are unaffected, since a repeated ROA covers exactly what the first one does.
- **Visible to**: operators whose ROA source contains repeats, who now get current RPKI state instead of a stuck import, and their users through `!f` filtering, RPKI-aware queries and notification mails.
- **Why**: a v4 bug with no upside. Josh decided on 2026-11-01 to fix it. `parity/status/run.sh` step 03 checks that v4 still fails on the file with repeats and that irrd-ng on that file ends up exactly where v4 does on the same file without them, apart from the one extra trust anchor row.

## DIV-005: irr_rpsl_submit works with passwords

- **v4** (`irrd/scripts/irr_rpsl_submit.py:552`): before sending, the tool filters passwords out of a debug line with `filtered_http_data.replace(password, b"REMOVED")`, which is `bytes.replace(str, bytes)`. That raises `TypeError` whenever the input has a `password:` line, so the tool exits 32 with `Some other error: TypeError • a bytes-like object is required, not 'str'` and sends nothing. Input that authenticates with a password can never be submitted with v4's tool.
- **irrd-ng**: the request is sent, and the reply is reported as for any other submission.
- **Visible to**: anyone who runs `irr_rpsl_submit` with `password:` lines, which now works.
- **Why**: a plain v4 bug that makes the tool unusable for password authentication, fixed in line with DIV-004. `parity/submit/run.sh` checks that v4's tool still fails, and compares irrd-ng with v4's tool with that one line corrected.

## DIV-006: native standby replication and the `ng_replication` key

- **v4**: a standby is a PostgreSQL streaming replica of the active's database, set up outside IRRd. `readonly_standby: true` tells IRRd not to write.
- **irrd-ng**: LMDB has no streaming replication, so irrd-ng has its own. The active keeps a log of every committed change to every table and serves it on a TCP port; a standby fetches a snapshot, then follows the log one transaction at a time, reconnecting and resuming after restarts. Both ends prove they hold a shared secret without sending it, and every frame is authenticated. `readonly_standby: true` keeps its v4 meaning, and turning it off with SIGHUP promotes the standby. One new top-level key configures this: `ng_replication` with `secret`, `interface` and `port` on the active, and `active_host` and `active_port` on a standby. It is checked after all of v4's checks, so a v4-valid file gets exactly v4's result. v4 itself rejects a file containing the key.
- **Visible to**: operators who run a standby; they replace their Postgres replication with this key. Nothing changes for anyone else.
- **Why**: decision D2 in PLAN.md. The stream is authenticated but not encrypted, so for now it must run over a private network or a tunnel; adding TLS is a Phase 10 item.

## Not a divergence: comment line stripping

v4's `split_paragraphs_rpsl` (`irrd/utils/text.py:69`) has an operator precedence slip, `strip_comments and line.startswith("%") or line.startswith("#")`, so `#` lines are always dropped and `%` lines only when `strip_comments` is set. Read literally that looks like a bug, but the behaviour it produces is the right one: RPSL treats `#` lines as comments everywhere, while NRTMv3 streams (the one caller that passes `strip_comments=False`) must keep `%` lines for `%START` and `%END`. Correcting the precedence would make irrd-ng keep `#` lines in NRTMv3 streams, which would then reject any mirrored object containing a whole-line comment and any stream with a `#` line after `%END`. irrd-ng therefore implements v4's behaviour, written out explicitly, and produces identical results.

## Accepted minor divergences

These are corner cases where irrd-ng cannot or does not match v4 exactly. None of them shows up on the fixture data from eight real registries or on the oracle corpora. P-01 to P-14 were reviewed and accepted on 2026-11-01, and P-15 to P-20 later the same day, on the condition that none of them changes what a client sees. They keep their P numbers because code and test comments refer to them.

### Configuration

- **P-01 Error order for unordered sets.** v4 builds `Unknown key(s) under source X: a, b` and `sources_default contains unknown sources: A, B` from Python sets, so the order changes from one start to the next. irrd-ng lists them in file order. No fixed order would match v4 every time.
- **P-02 Configurations that crash v4.** Where v4 dies with a traceback, irrd-ng reports `Errors found in configuration, unable to start: unexpected <Exception>: <v4's message>`, or `...continuing with current settings: unexpected ...` on SIGHUP, and keeps running on SIGHUP.
- **P-03 NRTMv4 key edge cases.** On curves other than P-256, a tampered point is rejected by v4 (`Invalid key`) and accepted by irrd-ng, which checks structure and length only. Damaged DER inside a certificate reports a different `ParseError` location. An OpenSSH key with an unsupported KDF prints a memory address in v4 and `Unsupported KDF` in irrd-ng. SSH certificate keys, unusual curve or algorithm names and hybrid-encoded P-256 points are approximated.
- **P-04 Unicode corners.** v4's `isnumeric()` accepts CJK numerals such as 一 and irrd-ng does not. Some non-ASCII URL hosts raise an NFKC error in v4 and not in irrd-ng. Escaped lone surrogates in YAML become U+FFFD.
- **P-05 Rare inputs.** An integer given where a path is expected is a file descriptor to v4 and "not a directory" to irrd-ng. Reading a setting through a list raises in v4 and reads as unset in irrd-ng. Some OS error texts differ between musl and glibc.
- **P-06 Password hasher values from the environment.** An invalid `IRRD_AUTH_PASSWORD_HASHERS_*` value makes v4 raise the first time an `auth:` line is checked. irrd-ng raises the same `AttributeError` once, when it builds the parser settings at startup.
- **P-07 Environment overrides for unconfigured sources.** v4 would honour `IRRD_SOURCES_X_AUTHORITATIVE` for a source missing from the file when rendering an object from that source. irrd-ng only reads per-source rendering settings for sources in the file.

### RPSL and key-certs

- **P-08 gpg checksum state across armor blocks.** When a later armor block in the same `certif` lacks its blank line, gpg fails the CRC because it does not reset its checksum. irrd-ng fails the same way with the same error, without computing gpg's exact checksum value, which v4 never shows.
- **P-09 Import note order.** The relative order of "Key expired" and "New signatures" notes is approximate when one `certif` holds several keys.
- **P-10 Re-importing a known key with extra user IDs.** irrd-ng assumes the primary user ID moves to the front again after the merge. Not yet tested against gpg.
- **P-11 Small gaps.** Python's final-sigma lowercasing is approximated (error text only, for attribute names containing a capital sigma). `geofeed` URLs with invalid bracketed hosts do not raise as Python 3.13 does. `render_rpsl_text()` returns text for an object without a source where v4 raises; v4's callers never do this.
- **P-12 Mangled key owner names.** gpg and python-gnupg turn non-ASCII names in `owner` into Latin-1 mojibake (`BÃ¶ing`). irrd-ng copies this exactly. It is listed because fixing it would be a visible divergence; it was accepted with the others as it is, so the mangling stays.

### Whois

- **P-13 Answer order v4 does not fix.** v4 builds `!g`, `!6` and `!a` answers by joining a Python set of prefix strings (`irrd/storage/preload.py`, `routes_for_origins`), and the `-i` error for an unsupported attribute joins the set from `lookup_field_names()`. Python randomises string hashing per process, so two v4 processes on the same data give different orders: on the Tier 1 fixtures, 242 of 3,863 whois items and 199 of 3,629 `/v1/whois/` items differ between two v4 instances, and only in order. No fixed order in irrd-ng can match v4 byte for byte. The harness accepts a permutation of v4's answer for exactly these cases, with the `A<len>` line still exact (`parity/corpus/whois/unordered.tsv`), and reports them as "equivalent", never as identical. irrd-ng uses one fixed order: prefixes by address family, then address, then length, and the unsupported attribute names sorted. The same applies to the `allow` header of an HTTP 405, which Starlette builds from a Python set, so v4 sends `GET, HEAD` or `HEAD, GET` depending on the process.
- **P-14 Objects with equal sort keys.** v4 orders object answers by `ip_first`, `asn_first`, `rpsl_pk` (and source priority where the query orders by source); the same `rpsl_pk` in two sources ties, and Postgres returns ties in no fixed order (seen on `!r0.0.0.0/0,M` between two v4 instances). The harness accepts a different order only within runs of objects with the same class, key and origin. irrd-ng breaks these ties by its internal object id, which follows the order objects were stored in, so its answer is stable from one start to the next.

### Store and tools

- **P-15 No gaps in `serial_global`.** v4's Postgres sequence keeps the values a rolled-back transaction used, so `serial_global` has gaps after a failed update. irrd-ng rolls the counter back with the transaction, so it has none. `serial_global` only appears in exports and the journal tables, and NRTM serving uses the per-source serials, which match.
- **P-16 One-line errors instead of tracebacks in the tools.** Where a v4 tool dies with a Python traceback, irrd-ng prints only the exception line or lines, without the stack frames. The exit code is the same. P-02 covers the same idea for configuration errors.
- **P-17 Schema tools on the embedded store.** `irrd_database_upgrade` and `irrd_database_downgrade` do not print alembic's own INFO lines (`Context impl PostgresqlImpl.` and similar). Downgrading to an older revision prints success and exits 0 but changes nothing, because the store has no alembic revisions.
- **P-18 `IRRD_NG_STORE_PATH`.** A new environment variable, defaulting to `/var/lib/irrd-ng`, sets where the store lives. There is deliberately no `irrd.yaml` key for it, so a v4 configuration stays valid for both.
- **P-19 Fixed order where v4 uses Python set order in loaders.** v4 lists unknown object classes, and applies the deletions in `irrd_update_database`, in Python set order, which changes between runs. It applies that tool's modifications in whatever order Postgres stores the rows, which is stable in practice but not defined. irrd-ng lists unknown classes in first-seen order and applies both deletions and modifications in key order, so the journal for one `irrd_update_database` run can list the same changes in a different order.
- **P-20 Small faithfulness gaps in stored metadata.** `rpsl_objects.ip_size` is derived from `ip_first` and `ip_last` instead of being stored. `database_status.updated` is the transaction time, not the moment of the statement. Store log lines come from an `irrd_ng.store` logger, which v4 does not have.

## Proposed, awaiting review

P-21 to P-29 came out of Phases 5 and 6, P-30 to P-39 out of Phase 8, P-40 to P-44 out of Phase 7, P-45 to P-48 out of the Phase 8 follow-up on the GraphQL transports, and P-49 to P-53 out of Phase 9. P-22 has since been withdrawn. Each of the others needs a decision: accept it, or keep it open as a bug to fix.

### RPKI, scope filter and route preference

- **P-21 Journal order inside one status batch.** When a ROA import, scope filter run or route preference run changes many objects at once, irrd-ng writes the journal entries in the store's key order. v4 writes them in the order its unordered table scan returns. The serials, operations and object texts are the same; only the order within the batch differs.
- **P-22 Withdrawn.** irrd-ng no longer reproduces v4's duplicate ROA failure, so its log text no longer matters (DIV-004).
- **P-23 Approximated parser errors in ROA import logs.** Rarer ujson error texts, and the Python dict printout of a malformed ROA record, are approximated in the log.
- **P-24 Order inside RPKI notification mails.** v4 lists objects, and the sources in the subject, in Python set order, which changes between runs. irrd-ng uses first-seen order.
- **P-25 Long non-ASCII mail headers.** irrd-ng writes a non-ASCII header as one encoded word where Python's email package splits a long one into several. Mail clients decode both to the same text.

### Serving data

- **P-26 No repeated NRTMv4 delta entries.** v4 reads the newest serial, the journal and the snapshot in separate queries, so an update landing in between can put the same journal entry at the end of one delta and the start of the next (4 times in 543 records in the serving churn test). irrd-ng reads them from one consistent view and never repeats an entry.
- **P-27 No NRTMv4 server lock files.** v4 creates `nrtm4-server-*.lock` files in `piddir`; irrd-ng runs everything in one process and uses in-process locks instead.
- **P-28 Deterministic NRTMv4 signatures.** irrd-ng's ES256 signatures are deterministic (RFC 6979); v4's are randomised. Both verify with the same key, and no client can tell them apart except by comparing two signatures of the same file.
- **P-29 Write-side checks and error text.** irrd-ng does not re-validate an Update Notification File's contents before writing it, which only matters in a race v4 cannot reach in practice. Python exception text in export and NRTMv4 server error logs is approximated.

### GraphQL, status, metrics and the event stream

- **P-30 Order of `rpslObjects` and the `*Objs` fields.** v4 runs these queries without `ORDER BY`, so rows come back in whatever order Postgres returns them, and a `recordLimit` below the number of matches returns arbitrary rows. irrd-ng uses its object order (P-14). Error paths that carry a row index follow the same order.
- **P-31 Set order in `asSetPrefixes`, `asnPrefixes` and `recursiveSetMembers`.** v4 builds the per-set and prefix order from Python sets, as in P-13. The harness accepts a permutation.
- **P-32 Order of GraphQL errors.** v4 lists errors in the order its threaded resolvers finish. irrd-ng lists them in execution order.
- **P-33 `sqlTrace`.** irrd-ng has no SQL, so it renders the SQL v4 would have run instead of running it, with columns in table order where v4 uses Python set order.
- **P-34 No template leak from `membersObjs`.** In v4, one `membersObjs` query permanently changes that HTTP worker's `-t as-set`, `-t route-set` and `-t rtr-set` templates, and possibly reference checks for submissions handled by the same worker. irrd-ng does not copy this.
- **P-35 Static files.** Only the GraphiQL files under `/static/` are served. Their `last-modified` and `etag` use the v4.5.4 release date, because v4's depend on when and where it was installed.
- **P-36 Event stream without Redis.** Changes are announced in-process. Writes by other processes, such as the command-line tools, are announced within 2 seconds, with one event per source per 2-second window. Compressed frame bytes and ping timing differ.
- **P-37 Row order in `/v1/event-stream/initial/`.** Follows irrd-ng's object order.
- **P-38 pydantic error text for invalid event stream messages.** Approximated.
- **P-39 LMDB map size in `/v1/status/`.** Not shown, because v4 prints nothing like it. The project brief (CLAUDE.md) asks for it to be shown; adding one line would change the status text, so it waits for a decision.

### Submissions and mail

- **P-40 Mail order.** Notification and reply mails go out in a fixed order; v4 sends them in Python set order, which changes between runs.
- **P-41 Multi-byte mail charsets.** Mail bodies in ASCII, UTF-8 and all of Python's single-byte codecs (windows-125x, iso-8859-x, koi8, mac and DOS code pages, with their aliases) decode exactly as in v4. Multi-byte charsets such as Shift_JIS, GB2312, Big5 and ISO-2022-JP are not supported: such a mail is logged as unprocessable and gets no reply, where v4 would decode it.
- **P-42 `From:` parsing.** The reply address is taken from `From:` with a simpler parser than Python's `email.utils`. Ordinary addresses give the same result.
- **P-43 Non-ASCII headers in a signed PGP/MIME part.** These are not re-encoded the way Python's email package would before the signature check, so such a signature can fail in irrd-ng and pass in v4.
- **P-44 Signature checks by sequoia, not gpg.** PGP signatures and key imports go through sequoia, so rare edge cases in key or signature formats can be judged differently. A `$2$` bcrypt hash, the oldest variant, is always refused; v4 leaves it to passlib, whose answer depends on its bcrypt backend.

### GraphQL transports

v4 4.5.4 never returns a result for a GraphQL query sent over the WebSocket at `/graphql/` or as a multipart request: IRRd's logging extension reads `request._json` after the query runs, which only exists for JSON bodies, so the query raises `AttributeError`. Over WebSocket the connection drops without a close frame, and a multipart request gets a plain 500. irrd-ng copies this, and the handshakes, protocol messages and multipart errors around it, byte for byte (`parity/corpus/graphql/transport.gq`). Making these transports actually work would be a deliberate divergence from a v4 bug, and is not done because no client can be relying on them today.

- **P-45 The query is not run.** Where v4 runs the query and then fails, irrd-ng fails without running it. The client sees the same bytes.
- **P-46 Multipart bodies are parsed in one piece.** v4 parses them in network-sized chunks, which only matters for some malformed bodies split across packets.
- **P-47 Multi-byte charsets in a multipart `charset=` parameter.** UTF-8, ASCII, Latin-1 and Python's single-byte codecs decode as in v4; multi-byte ones such as UTF-16 fall back to Latin-1.
- **P-48 Lone surrogates in a WebSocket message `id`.** Echoing one back crashes v4's handler; irrd-ng escapes it.

### Daemon and logging

- **P-49 Partial `logging_config_path`.** v4 executes the file as Python and passes its `LOGGING` dict to `logging.config.dictConfig()`. irrd-ng reads the file as data instead. It supports stream, file, syslog (Unix socket or UDP) and null handlers, formatters, and levels, handlers and propagation per logger. Filters, custom classes, self-rotating handlers and `disable_existing_loggers: True` are not reproduced, `lineno` and `funcName` are approximated, and anything left out is named in a warning at startup. A file it cannot read falls back to stderr with a warning.
- **P-50 Primary group after dropping privileges.** python-daemon only calls `initgroups()`, so v4 keeps root as its primary group. irrd-ng also switches to the configured `group`.
- **P-51 Process-model log lines.** irrd-ng is one process, so it does not log `sent SIGHUP/SIGTERM to child processes [...]` or `Some processes left alive`, and logs one reload line where v4 logs one per process.
- **P-52 SIGHUP does not restart the HTTP server.** v4's uvicorn restarts its workers on SIGHUP, which drops open event-stream WebSockets and in-flight requests. irrd-ng reloads in place.
- **P-53 No double fork.** v4's python-daemon forks twice; irrd-ng starts itself again in a new session instead, because forking a process that may have threads is not safe in Rust. The daemon stays a session leader, with no functional effect.

