# IRRd-NG project plan

Plan of record, agreed with Josh on 31 October 2026. Decisions D1 to D4 are settled and are not re-asked.

## Goal

A Rust replacement for IRRd 4.5.4 that an operator can drop in: stop `irrd`, run a one-shot import from the v4 Postgres database, start `irrd-ng` with the same `irrd.yaml`, and no client notices. Parity comes first. Speed, memory and overhead come second, and every claim about them is backed by numbers from the load bench against v4.

The web UI is out of scope for this plan, but its data (users, permissions, API tokens, WebAuthn, change log) is carried through the import untouched.

## Baseline

- IRRd **4.5.4**, tagged 19 October 2026 (commit `8e8080dab744`). It is the latest stable release, and it is also the exact version the production reference server reports for `!v`, so the pinned baseline and the live reference agree.
- There is no official v4 container image. We build one from the tagged source, pin it by digest, and record version, commit and digest in `parity/BASELINE`.
- Bumping the baseline (4.5.5, 4.6) is a separate, deliberate change with its own parity run.

## What v4 is, measured

v4 is about 25,800 lines of Python (excluding tests, vendored code and migrations), with about 22,400 lines of tests. At runtime it is a daemon that forks one whois worker process per allowed connection, a uvicorn HTTP server with its own workers, a preload manager that keeps origin and set data warm in Redis, and a scheduler that starts a child process for each mirror import or export every 15 seconds. All persistent state is in PostgreSQL (13 tables, 26 Alembic migrations). Redis carries the preload cache, the event stream and signalling between processes.

| Area | v4 source lines | v4 test lines | irrd-ng crate | Phase |
|---|---|---|---|---|
| RPSL parsing, object model, validation | 2,212 | 1,124 | `rpsl` | 1 |
| Configuration | 1,324 | in module | `config` | 1 |
| Storage, queries, preload | 3,506 | 1,834 | `store` | 2 |
| Whois server and query parser | 998 | 1,309 | `query` | 3 |
| File import, NRTMv3, exports | 1,588 | 2,589 | `nrtm` | 4, 6 |
| NRTMv4 client and server | 1,030 | 1,237 | `nrtm` | 4, 6 |
| RPKI, scope filter, route preference | 974 | 1,278 | `rpki` | 5 |
| Submissions, auth, notifications, suspension | 2,194 | 4,563 | `auth` | 7 |
| REST, status, metrics, event stream | 1,221 | 1,064 | `http` | 8 |
| GraphQL | 851 | 1,178 | `http` | 8 |
| CLI tools | 2,155 | 1,563 | `cli` | throughout |
| Daemon and process management | 260 | none | `cli` | 9 |
| Web UI | 2,375 | 2,542 | deferred | later |

### What the production reference can and cannot test

The reference server carries seven sources: RPKI, RADB, APNIC, RIPE, ARIN, AFRINIC and LACNIC. Every one is a non-authoritative mirror with RPKI filtering on, the scope filter off, no route preference and no local journal. ARIN, AFRINIC, LACNIC and RADB are class-filtered to `as-set`, `aut-num`, `route-set`, `route` and `route6`. RIPE and APNIC are unfiltered.

That makes it a good reference for the read path at real scale: whois, `/v1/whois/`, GraphQL, set expansion and RPKI status. It cannot exercise submissions, auth, notifications, email, NRTMv3 or NRTMv4 serving, exports, the scope filter, route preference or suspension. Those are tested only against the local pinned v4 container, where we configure authoritative sources and journals ourselves.

## Corrections to the spoke CLAUDE.md

Found while reading the v4 source. These get applied in Phase 0.

1. The control tool is `irrdctl`, not `irrctl`. Its subcommands are `user_mfa_clear`, `user_change_override` and the `nrtm4` group (`client-clear-known-keys`, `generate-private-key`, `server-show-public-key`).
2. Two CLI tools are missing from the list: `irr_rpsl_submit` (a client that submits to the HTTP API) and `irrd_load_pgp_keys`. The full set is 12 binaries.
3. Two HTTP endpoints are missing: `/metrics/` (Prometheus, new in 4.5, behind `server.http.status_access_list`) and `/v1/event-stream/initial/` (the initial download that pairs with the WebSocket).
4. v4 sends mail over SMTP to `email.smtp` using `smtplib`. There is no sendmail path, so the "local sendmail binary" option does not match v4. Use `lettre` as an SMTP client.
5. The whois list also needs `!e` (set exclusions), `!J` (JSON status), `!fno-rpki-filter`, `!fno-scope-filter`, `!fno-route-preference-filter`, `-q`, `-t`, `-K`, `-V`, and `-F` and `-r`, which v4 accepts and ignores.
6. `readonly_standby` depends on PostgreSQL streaming replication. There is no direct LMDB equivalent, see D2.
7. `/` redirects to `/ui/` in v4. With the web UI deferred, irrd-ng keeps the redirect and `/ui/` returns 404, which goes in `docs/divergences.md`.
8. `auth.gnupg_keyring` points v4 at a GnuPG home directory, and v4 shells out to `gpg`. irrd-ng needs its own key store, see the PGP call below.

## Decisions

Stack, storage engine, crate layout, targets and conventions are as written in CLAUDE.md and are not repeated here.

### Settled with Josh (31 October 2026)

**D1. Repository and CI: GitHub with Actions.** The spoke becomes its own git repo (the hub ignores `spokes/*`) hosted at https://github.com/JoshFinlayAU/irrd-ng, with the full CI/CD pipeline in Actions. Still needed before the first push: `gh` installed and authenticated on this box.

**D2. Standby: native replication, built in Phase 9.** v4 standbys are PostgreSQL streaming replicas, which have no LMDB equivalent. A standby irrd-ng follows the active over an authenticated stream of the store's own change log (every table, not only RPSL objects), and `readonly_standby: true` keeps its v4 meaning. Pointing the standby at the active needs one new irrd-ng key, which is a listed divergence.

**D3. Full-scale reference data: a read-only `pg_dump` of the reference server on a scratch VM.** The dump is restored into a frozen v4 4.5.4 on a dedicated VM (8 vCPU, 32 GB RAM, 80 GB SSD, sized from the reference server's measured 14 GB database on 2026-10-31), which also hosts the load bench, and irrd-ng imports the same dump. Approved as the one sanctioned use of the reference server's database: read-only, a dump only, never a write and never the importer pointed at the live server. This box has about 5 GB of free RAM and 36 GB of free disk with other containers running, so it runs Tier 1 only. The VM is `irrd-ng-parity`, created 31 October 2026 with Docker installed; its host and access details are in the spoke's private memory (`memory/parity-vm.md`).

**D4. Working mode: autonomous to done.** The irrexplorer-ng model. Questions were asked once, here. From Phase 0 on, the phases run through to the Definition of Done without stopping for confirmation. Every judgement call goes into `memory/decisions-log.md` with its reason, and Josh gets a short report at the end of each phase. When something is ambiguous, pick the option that best preserves v4 parity, log it and carry on. When something is blocked, take the next-best option inside these decisions, log it and keep going. Stop only if no fallback exists, and say so plainly.

### Technical calls I will make unless you object

- **PGP.** `sequoia-openpgp` with its pure-Rust crypto backend, so the static musl build has no C dependencies. v4 derives key-cert attributes (`fingerprint`, `owner`, `method`) at parse time, so this lands in Phase 1, and it is checked against v4 on every key-cert in the cached dumps, including expired, revoked and subkey-heavy keys. If parity cannot be reached on an edge case, the fallback is calling `gpg` the way v4 does, behind a config switch.
- **Password hashes.** DES crypt, MD5 crypt and bcrypt, including 4.5.4's new rejection of bcrypt hashes that cannot be parsed.
- **GraphQL.** The schema is built at startup from v4's SDL using async-graphql's dynamic schema, rather than from code-first types, so drift from v4 cannot go unnoticed. The v4 SDL is checked in and a test compares introspection output. Error text from graphql-core does not come free with async-graphql; the common messages get mapped and the rest are listed as divergences.
- **Process model.** One process. A tokio runtime handles network I/O, a dedicated OS thread is the single LMDB writer fed by a channel, and readers use their own read transactions (heed's `read-txn-no-tls`). `server.whois.max_connections` becomes a connection limit that queues like v4's fixed worker pool. `server.http.workers` is accepted and sizes the HTTP worker threads.
- **No preload cache.** The LMDB secondary indexes answer `!g`, `!6`, `!a` and `!i` straight from the page cache. A small in-process cache is allowed only if the load bench shows a hot spot, with RSS measured before and after.
- **No Redis.** Event stream fan-out and SIGHUP propagation use in-process channels.
- **Fetching.** v4 imports from http(s), ftp and local files, gzipped or not. `reqwest` with rustls for HTTP and `suppaftp` for FTP, with DNS done natively so the static build works.

### To verify in Phase 0

- The NRTMv4 draft version. The 4.5.0 release notes say draft-ietf-grow-nrtm-v4-08, while `docs/users/mirroring.rst` says -07. The code decides.
- Signing keys for NRTMv4 are P-256 (`ECKey` via joserfc, ES256 JWS). Confirm the exact JWS and PEM formats from the code.

## Architecture

The crate layout is the one in CLAUDE.md. The store is one LMDB environment holding these databases:

- `objects`: keyed by source, class and primary key. Each record holds the verbatim object text, the parsed attributes, metadata (created, updated, last serial) and the status flags for RPKI, scope filter, route preference and suppression.
- Secondary indexes: case-folded primary key (for `!m` and RIPE text search), `mnt-by`, `origin`, `member-of`, `mbrs-by-ref`, set `members` (for expansion), v4's lookup fields (for `-i`), and separate IPv4 and IPv6 prefix indexes keyed for exact, less-specific and more-specific lookups.
- `journal` per source, keyed by serial, written in the same transaction as the object change.
- `status` (v4's `database_status`), `roa`, `suspended`, `protected_names`, `settings`, NRTMv4 client and server state.
- Web UI tables (`auth_user`, `auth_permission`, `auth_mntner`, `auth_api_token`, `auth_webauthn`, `change_log`) stored as faithful copies. `auth_api_token` is live, because API keys authenticate `/v1/submit/`.
- `meta`: schema version and map size history.

The writer batches mirror and ROA updates into large transactions and never holds a write transaction across I/O. The event stream and NRTM serving renew their read transactions so pages can be reused. Map size is set from the import, grows automatically with headroom, and is reported in `/v1/status/`.

## Testing and parity strategy

- **Unit tests.** Port v4's test expectations where they pin behaviour, especially the RPSL samples (`irrd/utils/rpsl_samples.py`) and validator error strings. Port what they assert, not how they are structured.
- **Tier 1 differential (every PR, hosted CI runner).** Pinned v4 plus Postgres and Redis in compose, loaded with small fixture dumps cut from real sources: a few thousand objects chosen to hit every class and every edge case we know of. All suites run (whois, http, graphql, nrtm, submit, cli) with byte diffs. Target: under 15 minutes.
- **Tier 2 scale (nightly and before release).** The full dataset from D3, the full query corpus, bgpq4 and peval sweeps over the largest AS-sets, and the load bench.
- **Tier 3 live spot checks.** Read-only queries against the reference server, compared only for objects whose source serial matches, to catch framing and format problems against a real deployment.
- **Mutation suites.** Identical submissions and NRTM streams go to both servers, then responses, mails (Date and Message-ID masked), journals and resulting object text are compared. v4's own `irrd/integration_tests/run.py` already drives two instances through submissions, mail and mirroring, and seeds these suites.
- **Three-way load check.** The harness loads the dumps into v4 with v4's loader, and into irrd-ng twice: once with irrd-ng's own loader and once with `import --from-postgres` from the v4 database. All three must agree, which tests the loader and the importer against each other.
- **Corpus.** v4 docs and tests, bgpq4 and peval invocations, the queries irrexplorer-ng makes, and anonymised query logs from the reference server if available. v4's `irrd/scripts/query_qa_comparison.py` is a ready-made two-instance whois comparator and bootstraps `parity/run.sh`.
- **Fuzzing and soak.** cargo-fuzz targets for the RPSL parser, the whois query parser and the NRTMv3 stream parser. A multi-day soak with mirroring and query load before release.
- **Divergences.** Every intentional difference goes in `docs/divergences.md` with a reason, and only after review. Expected output is never edited to make a diff pass.

## Phases

Each phase ends with its exit criteria met, CI green, and the parity suites for that phase passing.

### Phase 0: Foundations

1. `git init` in the spoke, `.gitignore`, first commit, push to the D1 remote.
2. Apply the CLAUDE.md corrections above, plus one found in Phase 0: v4 has no NRTMv4 HTTP routes; it writes the files for an external web server.
3. Toolchain: pin `rust-toolchain.toml` to current stable (1.99.0 on this box today), add the musl and aarch64 targets, install zig, cargo-zigbuild and cargo-nextest, and put `~/.cargo/bin` on PATH for sessions (it is installed but not on PATH now). Record versions in memory.
4. Cargo workspace with every crate as a skeleton, `#![deny(unsafe_code)]` outside `store`, mimalloc, a `messages.rs` per crate, workspace lints.
5. `vendor/irrd-v4` as a read-only submodule pinned to v4.5.4.
6. v4 reference image built from the tag, compose with Postgres and Redis, `parity/up.sh` and `parity/down.sh`, and `parity/BASELINE`.
7. Extract the reference material from v4: GraphQL SDL, `-t` templates for every class, every user-facing message string, default config, known keys and their reload behaviour. Settle the two Phase 0 checks above.
8. Fetch the public dumps (RADB, RIPE non-auth, ARIN, AFRINIC, LACNIC, APNIC, ALTDB, NTTCOM, LEVEL3) into `parity/.cache/` and cut the Tier 1 fixture subsets.
9. CI: fmt, clippy, nextest, doc tests, builds for all four targets, a static-link check on the musl artefacts, and cargo-deny for licences and advisories.

**Exit:** CI green on all four targets with the empty workspace. `parity/up.sh` brings up v4 4.5.4 answering `!v`.

### Phase 1: Config and RPSL core

1. `config`: the full `irrd.yaml` model including sources, `access_lists`, `source_aliases`, `compatibility` and per-class `auth.set_creation`. v4's defaults, identical validation error strings, identical unknown-key handling, Postgres and Redis keys accepted with a single startup notice, and each key tagged as SIGHUP-reloadable or restart-only.
2. `rpsl`: the parser (continuation lines, comments, case rules, verbatim text), all 19 object classes, every field type (prefixes, ASNs with the asdot option, set names, auth hashes, dates, emails), strict and non-strict modes, normalisation, templates for `-t`, and key-cert parsing with PGP.

**Exit:** the ported v4 RPSL tests pass, and every object in every cached dump parses to the same fields, messages and normalised text as v4.

### Phase 2: Store, loaders and v4 import

1. LMDB schema and indexes, the writer thread, batching, map auto-grow, schema versioning with a migration framework and a fixture test that opens the previous version.
2. `irrd_load_database` and `irrd_update_database` with v4's flags, output and exit codes.
3. `irrd-ng import --from-postgres`: read-only against the source, serial-preserving, idempotent upsert, covering RPSL objects, journal, status, ROAs, suppression, protected names, NRTMv4 state and the web UI tables.
4. `irrd_database_upgrade` and `irrd_database_downgrade` as schema checks that exit 0 where v4 would.

**Exit:** the three-way load check agrees on every cached dump. Import time, store size and RSS are recorded against v4's Postgres size and load time.

### Phase 3: Query engine and whois

1. IRRd style: every command listed in CLAUDE.md and the corrections, `A<len>`/`C`/`D`/`F` framing, multi-command mode with `!!`, `!t` timeouts, `!n` client identification, `!s` sources with `sources_default` and `source_aliases`, `!e` exclusions, the `!f` filter overrides, set expansion depth and loop handling, and `!g`/`!6`/`!a` aggregation and dedupe.
2. RIPE style: `-l -L -M -x`, `-i`, `-s -a`, `-T`, `-t`, `-K`, `-V`, `-k`, `-q`, `-g` (wired to Phase 6), the `-F -r` no-ops, text search, and the `compatibility` switches.
3. Server: access lists, connection limit, timeouts, keepalive, error strings.
4. `/v1/whois/` over the same engine.
5. First benchmark: whois QPS, p50 and p99 latency, RSS, against v4.

**Exit:** the whois corpus is byte-identical on Tier 1 and Tier 2, and bgpq4 and peval output is identical for the largest AS-sets.

### Phase 4: Mirroring client

1. Scheduler, `import_source` (http, ftp, file, gzip), `import_serial_source`, `import_timer`, `object_class_filter`, `strict_import_keycert_objects`.
2. NRTMv3 client with `nrtm3_client_timeout`.
3. NRTMv4 client: notification file, JWS verification, key rotation, snapshot and delta handling, automatic recovery.
4. `irrd_mirror_force_reload`, `irrdctl nrtm4 client-clear-known-keys`, and `database_status` updates including 4.5's "RPSL data updated" timestamp.

**Exit:** irrd-ng and v4 mirror the same upstreams side by side for 7 days with identical object sets and status after each cycle.

### Phase 5: RPKI, scope filter, route preference, suppression

1. ROA import from `rpki.roa_source`, SLURM, the RPKI pseudo-IRR source with `pseudo_irr_remarks`, per-object validation status and transitions, and `notify_invalid` mails.
2. Scope filter on prefixes and ASNs, per-source exclusions.
3. Route object preference with its update timer.
4. Suppressed objects hidden or shown correctly in every surface, and journal entries on every status transition.

**Exit:** every object's statuses match v4 across the full dataset, and the journal entries produced by status transitions are identical.

### Phase 6: Serving data

1. NRTMv3 server (`-g`): access lists, unfiltered lists, serial range and days limits, response header, dummification.
2. Exports: `export_destination`, `export_destination_unfiltered`, `export_timer`, serial files.
3. NRTMv4 server: snapshot, delta and notification file generation, ES256 JWS signing, key rotation with `nrtm4_server_private_key_next`, snapshot frequency, local path.
4. `irrd_expire_journal`, `irrdctl nrtm4 generate-private-key` and `server-show-public-key`.

**Exit:** v4 mirrors from irrd-ng, and irrd-ng from v4, over both NRTMv3 and NRTMv4 through a churn test with no divergence. Exported files are byte-identical.

### Phase 7: Submissions and auth

1. Submission parser for email and HTTP, password, override, PGP and API key auth, mntner semantics, `authenticate_parents_route_creation`, set creation rules, protected names, non-strict mode, `authoritative_retain_last_modified`.
2. Notifications (`notify`, `mnt-nfy`, `upd-to`) and reply mails.
3. `irrd_submit_email`, `/v1/submit/`, `irr_rpsl_submit`, `irrd_load_pgp_keys`, `irrd_set_last_modified_auth`.
4. Suspension and `/v1/suspension/`.
5. The web-UI-adjacent `irrdctl` commands: `user_mfa_clear` and `user_change_override`.

**Exit:** the mutation suite is identical across responses, mails, journals and resulting objects.

### Phase 8: HTTP APIs

1. GraphQL: identical schema, every resolver (`rpslObjects` with journal access, `databaseStatus`, `asnPrefixes`, `asSetPrefixes`, `recursiveSetMembers`), `sqlTrace` accepted, and the GraphiQL explorer page.
2. `/v1/status/`, `/metrics/`, the event stream WebSocket and `/v1/event-stream/initial/`.

**Exit:** the http and graphql suites are byte-identical, or order-insensitive with a divergence entry where v4's own JSON key order is not stable.

### Phase 9: Daemon, operations and standby

1. `irrd` daemon: flags, daemonising, pidfile, user and group drop, SIGHUP reload with exact per-key semantics, SIGTERM shutdown timing, log format and levels.
2. `log.logging_config_path` is a Python `dictConfig` file. Support the common shapes (file, syslog, level) and log a notice for the rest, as a divergence.
3. Standby per D2.

**Exit:** a drop-in rehearsal on a copy of a real v4 deployment (stop v4, import, start irrd-ng with the same config) passes every suite.

### Phase 10: Performance, hardening and release

1. Load bench against v4 for whois, HTTP and GraphQL: QPS, p50 and p99, RSS, import time, mirror catch-up time. Profile and fix hot paths without changing output.
2. Fuzzing, soak test, `/code-review` and `/security-review`, with every confirmed finding fixed.
3. Release artefacts: static musl for x86_64 and aarch64, glibc builds, the multicall binary with symlinks, a systemd unit, checksums.
4. Docs: README, migration runbook, `docs/divergences.md` reviewed end to end.
5. Pilot: a shadow instance next to a real v4 on the D3 host, then a cut-over rehearsal.

**Exit:** the Definition of Done.

## Sequencing and size

Phases 0 to 3 are strictly in order. Phases 4, 5 and 6 can overlap, with 4 before 6. Phase 7 needs 1, 2 and the journal work in 6. Phase 8 needs 3 and 5. Phases 9 and 10 come last.

Relative size: Phase 0 small, 1 medium, 2 medium, 3 large, 4 medium, 5 medium, 6 medium, 7 large, 8 large, 9 medium, 10 medium. Phases 3, 7 and 8 carry most of the byte-level parity risk.

## Definition of Done

- Every in-scope surface passes Tier 1 and Tier 2 parity with zero unexplained diffs. Every intentional difference is in `docs/divergences.md` and has been reviewed.
- The drop-in rehearsal passes on a copy of a real v4 deployment, with NRTM serials preserved so downstream mirrors carry on without a reload.
- The load bench shows irrd-ng ahead of v4 on QPS, latency and RSS, with the numbers recorded in the repo.
- Static musl builds for x86_64 and aarch64 and glibc builds for both, CI green on all four.
- Web UI data survives the import intact and is readable by a later phase.

## Risks

1. **Implicit ordering in v4.** Only 12 places in `irrd/storage/queries.py` ask Postgres for an order. Everything else comes back in whatever order the planner picks, which can change with table size, vacuum state or Postgres version. Where v4's own order is not stable, byte parity is not well defined. Mitigation: catalogue these in Phase 3, match the order v4 produces in practice where it is deterministic, and compare as sets with a divergence entry where it is not.
2. **Python formatting leaks into output.** IPy prefix formatting, ujson serialisation, datetime formats and set or dict iteration order all show up on the wire. Catalogue them in Phase 0 from the source, not the docs.
3. **GraphQL error text** from graphql-core will not match async-graphql without deliberate mapping.
4. **PGP edge cases** between GnuPG and sequoia (expired and revoked keys, subkeys, unusual packets).
5. **`logging_config_path`** has no faithful Rust equivalent.
6. **Standby** (D2) is new engineering, not a port.
7. **A moving baseline.** v4 may release 4.5.5 or 4.6 during the build. Watch upstream releases and bump deliberately.
8. **Dev box resources.** Fine for Tier 1, not for full-scale Tier 2 or the bench (D3).
9. **LMDB constraints.** One writer, a pre-sized map, and long read transactions blocking page reuse. Designed for in Phase 2 and proven in the soak test.
10. **Size.** About 26,000 lines of v4 with 22,000 lines of tests, matched at byte level. The estimates above will move once Phase 3 shows how much of v4's behaviour is implicit.
