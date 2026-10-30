# IRRd-NG — software spoke

A full drop-in replacement for IRRd v4, written in Rust. The goal is feature parity with IRRd v4, with a strong focus on **speed, memory efficiency and low overhead**. A v4 operator should be able to stop `irrd`, run a one-shot import, start `irrd-ng` with the same `irrd.yaml`, and have no client notice the change.

Inherits the hub's global rules (see `../../CLAUDE.md`). This file adds spoke-specific context.

## Scope and compatibility contract

**Parity baseline: IRRd 4.5.x, latest stable.** Record the exact patch version and container digest in `parity/BASELINE` and use it everywhere. Bumping it is a deliberate, separate change.

These surfaces must behave **exactly like v4**. Any difference is a bug unless it is listed in `docs/divergences.md`:

1. **Wire protocols**
   - whois on TCP 43, both query styles:
     - IRRd style: `!g !6 !i !a !j !m !o !n !r !s !t !v !!`, plus multi-command / keepalive mode.
     - RIPE style: `-i -l -L -M -x -s -T -k -g`, and so on.
   - Byte-identical responses, including `A<len>`/`C`/`D`/`F` framing, error strings, trailing newlines and object/attribute ordering.
   - NRTMv3 serving (`-g`) and mirroring client.
   - NRTMv4 client and server (as present in 4.5).
   - Email submission (`irrd_submit_email` on stdin) and its reply mails.
2. **HTTP APIs** (web UI excluded, see below):
   - `/v1/whois/`
   - `/v1/submit/`
   - `/v1/status/`
   - `/v1/suspension/`
   - `/graphql`, with the same schema, field names, nullability and error shapes
   - the event stream WebSocket
   - NRTMv4 HTTP endpoints
3. **`irrd.yaml`**: same keys, defaults, validation errors and SIGHUP reload semantics. Unknown or removed keys get the same treatment v4 gives them. Postgres/Redis keys (`database_url`, `redis_url`, …) are accepted and ignored, with a single startup notice.
4. **CLI tools**: same binary names, flags, exit codes and output:
   - `irrd`
   - `irrd_submit_email`
   - `irrd_load_database`
   - `irrd_update_database`
   - `irrd_mirror_force_reload`
   - `irrd_set_last_modified_auth`
   - `irrd_expire_journal`
   - `irrctl`
   - `irrd_database_upgrade`/`downgrade`. These become no-ops or schema checks for the embedded store, and must exit 0 in the same situations as v4.

   Ship these as one multicall binary with argv[0] dispatch, plus symlinks.

Also in scope, with semantics as in v4:
- RPSL parsing, validation and auth (CRYPT-PW, MD5-PW, BCRYPT-PW, PGPKEY, API keys)
- RPKI/ROA import and route validation
- scope filter
- route object preference
- object suppression states
- set expansion, with the same recursion depth and loop handling

**Deferred, not in phase 1:** the v4 web UI (user accounts, 2FA, mntner migration). Don't build it yet. Do keep its data from v4 (users, auth, API keys) intact through the import so a later phase can serve it.

Before saying "v4 does X", check the v4 source at the pinned tag (`vendor/irrd-v4/`, a read-only checkout) or the differential harness. Don't rely on memory or the docs alone.

## Output Testing

To avoid the overhead of running our own fully loaded and synchronised IRRd server for the purpose of testing against, we can leverage on the production IRRd server: the reference server (login as root and the production SSH key).

## Stack

- **Rust stable**, with the version pinned in `rust-toolchain.toml`. Edition 2021+. Cargo workspace.
- **Storage:** an embedded mmap B-tree engine (LMDB via `heed`). There is no Postgres or Redis at runtime.
  - One writer at a time, many lock-free readers. Queries run on read transactions and never block on imports or NRTM updates.
  - Secondary indexes are separate tables: by key, by mnt-by, by origin, by member-of/mbrs-by-ref, and a prefix radix index for `!r` with exact/less/more-specific lookups.
  - The journal (NRTM serials) and ROA/scope state live in the same environment, so updates commit atomically.
- **v4 import:** `irrd-ng import --from-postgres <dsn>` is a one-shot, read-only migration from a v4 4.5.x database (`rpsl_objects`, `rpsl_database_journal`, `database_status`, ROA/suppression tables, web-UI auth tables). It must preserve serials so NRTM mirrors continue without a reload. Never write to the source DB. Allow re-runs without duplication (upsert).
- **Runtime:**
  - `tokio` for async
  - `hyper`/`axum` for HTTP
  - `async-graphql` for GraphQL, with the schema checked against the v4 SDL dump
  - a maintained serde YAML crate for `irrd.yaml`
  - `lettre` or the local sendmail binary, matching v4 config, for mail
- **Allocator:** `mimalloc` globally. musl's malloc is far too slow for this workload.
- **Targets (Linux only):**
  - `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`: static, the primary release artefacts
  - `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`
  - Cross-build with `cross` or `cargo zigbuild`. No macOS or Windows code paths or CI.
  - **CI/CD:** Complete GitHub CI/CD tooling for the build and testing pipeline.

Suggested layout:

```
crates/
  rpsl/        # parser, object model, validation (no I/O)
  store/       # LMDB schema, indexes, journal, migrations
  query/       # whois query engine (IRRd + RIPE styles), set expansion
  nrtm/        # v3 + v4 client/server
  http/        # REST, GraphQL, event stream
  auth/        # mntner auth, PGP, submissions/notifications
  rpki/        # ROA import, validation, scope filter, route preference
  import-v4/   # Postgres → store migration
  config/      # irrd.yaml model + validation
  cli/         # multicall binary: irrd, irrd_*, irrctl
parity/        # differential harness, query corpus, baseline pin
bench/         # criterion + load-generator scenarios
```

## How to run / build / test

Before claiming a change works, run these:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace          # unit + integration
cargo test --doc --workspace
```

Release and cross builds:

```sh
cargo build --release
cargo zigbuild --release --target x86_64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl
# glibc: same with *-unknown-linux-gnu.
# Verify static: `file target/<musl-target>/release/irrd` → "statically linked"
```

Run locally:

```sh
./target/release/irrd --config dev/irrd.yaml --foreground
whois -h 127.0.0.1 -p 8043 '!iAS-EXAMPLE,1'
bgpq4 -h 127.0.0.1:8043 -S RADB AS-EXAMPLE    # real-client smoke test
```

**Differential parity testing** proves parity:

```sh
parity/up.sh          # docker compose: pinned IRRd 4.5.x + postgres + redis
parity/load.sh        # fetch/cached IRR dumps → load into BOTH v4 and irrd-ng
parity/run.sh         # replay corpus against both, byte-diff responses
parity/run.sh --suite graphql|http|nrtm|submit|cli
parity/down.sh
```

How the harness works:
- It uses real dumps (RADB, RIPE non-auth, ALTDB, NTTCOM, LEVEL3, …), cached in `parity/.cache/`. They are git-ignored and never committed.
- The corpus is replayed against both servers and responses are byte-diffed.
- Mutation suites send identical submissions and NRTM streams to both, then compare responses, notification mails and journal contents.
- New query corpora come from anonymised real query logs and bgpq4/peval invocations.
- A failing diff blocks merge. Fix the code, or add a reviewed entry to `docs/divergences.md`. Never "update the expected output" to make a test pass.

Benchmarks: `cargo bench -p query` and `bench/load.sh`, which runs a whois/HTTP load generator against both v4 and irrd-ng. Report p50/p99 latency, QPS, RSS and import time vs v4. Performance claims need numbers from this, not intuition.

## Conventions

- **Parity first, then speed.** An optimisation that changes output, even whitespace, ordering or the error text, is a regression.
- **Hot paths:**
  - zero-copy reads from mmap (borrow `&[u8]`/`&str` from the read txn)
  - no per-query heap churn
  - pre-serialised object text stored alongside parsed fields
  - avoid `String` formatting in response loops and write straight into the socket buffer
  - check for `clone()` in query paths
- **Memory:** measure RSS under the load bench for any change touching indexes or caches. Prefer the OS page cache (mmap) over in-process caches.
- No `unsafe` outside `store/`, and every `unsafe` block gets a `// SAFETY:` comment. `#![deny(unsafe_code)]` in all other crates.
- Errors use `thiserror` in libraries and `anyhow` only in `cli/`. User-facing error strings are copied verbatim from v4 and kept in one place per crate (`messages.rs`).
- Logging uses `tracing`. Log levels and important messages should roughly match v4 so operators' log alerts keep working.
- On-disk format changes need a store schema version bump, a migration and a test that opens the previous version's fixture.
- Every bug fix or parity fix adds a regression case to the parity corpus or a unit test.
- Commits use Conventional Commits (`feat(query): …`, `fix(nrtm): …`, `parity: …`, `perf: …`). Branches are `feat/…`, `fix/…`, `perf/…`. PRs that touch protocols include parity run output, and perf PRs include bench numbers.

## Gotchas

- v4's ordering is often implicit, e.g. Postgres query order, Python dict order and set-expansion order. Find out what v4 actually emits and copy it deliberately. Don't assume it's sorted.
- `!g`/`!6`/`!a` aggregate and dedupe prefixes in a particular way. bgpq4 and peval depend on the exact `A<len>` byte count.
- RPSL case-folding, continuation lines (`+`, whitespace, tab), comments and attribute normalisation differ between keys, the stored text and responses. Store the original text verbatim.
- NRTM serials must survive the import unchanged, or every downstream mirror will need a full reload.
- `irrd.yaml` reload on SIGHUP only applies some keys. Others need a restart, exactly as in v4.
- LMDB has one writer at a time. Batch mirror and ROA updates into large transactions, and never hold a write txn across an await or network I/O. Long-lived read txns stop page reuse, so the event stream and NRTM serving must renew theirs.
- LMDB map size has to be configured ahead of time. Size it from the import, auto-grow with headroom, and surface it in `/v1/status/`.
- Static musl builds can't use the glibc resolver or NSS. Do DNS and mail delivery natively or through configured binaries.
- The differential container needs its own Postgres and Redis. Never point the harness or importer at a production v4 database without asking first.
