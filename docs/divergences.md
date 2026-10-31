# Divergences from IRRd v4

irrd-ng matches IRRd 4.5.4 byte for byte on every surface listed in CLAUDE.md. This file is the complete list of places where it deliberately does not. Anything that differs from v4 and is not listed here is a bug.

Each entry says what v4 does, what irrd-ng does instead, who can see the difference, and why. Entries are added only after review, never to make a failing parity diff pass.

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

## Not a divergence: comment line stripping

v4's `split_paragraphs_rpsl` (`irrd/utils/text.py:69`) has an operator precedence slip, `strip_comments and line.startswith("%") or line.startswith("#")`, so `#` lines are always dropped and `%` lines only when `strip_comments` is set. Read literally that looks like a bug, but the behaviour it produces is the right one: RPSL treats `#` lines as comments everywhere, while NRTMv3 streams (the one caller that passes `strip_comments=False`) must keep `%` lines for `%START` and `%END`. Correcting the precedence would make irrd-ng keep `#` lines in NRTMv3 streams, which would then reject any mirrored object containing a whole-line comment and any stream with a `#` line after `%END`. irrd-ng therefore implements v4's behaviour, written out explicitly, and produces identical results.

## Accepted minor divergences

These are corner cases where irrd-ng cannot or does not match v4 exactly. None of them shows up on the fixture data from eight real registries or on the oracle corpora. All of them were reviewed and accepted on 2026-11-01. They keep their P numbers because code and test comments refer to them.

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
- **P-12 Mangled key owner names.** gpg and python-gnupg turn non-ASCII names in `owner` into Latin-1 mojibake (`BÃ¶ing`). irrd-ng copies this exactly today. Fixing it would be a visible divergence, so it is listed here for a decision rather than changed.

### Whois

- **P-13 Answer order v4 does not fix.** v4 builds `!g`, `!6` and `!a` answers by joining a Python set of prefix strings (`irrd/storage/preload.py`, `routes_for_origins`), and the `-i` error for an unsupported attribute joins the set from `lookup_field_names()`. Python randomises string hashing per process, so two v4 processes on the same data give different orders: on the Tier 1 fixtures, 242 of 3,863 whois items and 199 of 3,629 `/v1/whois/` items differ between two v4 instances, and only in order. No fixed order in irrd-ng can match v4 byte for byte. The harness accepts a permutation of v4's answer for exactly these cases, with the `A<len>` line still exact (`parity/corpus/whois/unordered.tsv`), and reports them as "equivalent", never as identical. irrd-ng uses one fixed order: prefixes by address family, then address, then length, and the unsupported attribute names sorted.
- **P-14 Objects with equal sort keys.** v4 orders object answers by `ip_first`, `asn_first`, `rpsl_pk` (and source priority where the query orders by source); the same `rpsl_pk` in two sources ties, and Postgres returns ties in no fixed order (seen on `!r0.0.0.0/0,M` between two v4 instances). The harness accepts a different order only within runs of objects with the same class, key and origin. irrd-ng breaks these ties by its internal object id, which follows the order objects were stored in, so its answer is stable from one start to the next.

## Proposed, awaiting review

These came out of the Phase 2 store and import work and were not in this file when the list above was accepted. Each needs a decision: accept it, or keep it open as a bug to fix.

### Store and tools

- **P-15 No gaps in `serial_global`.** v4's Postgres sequence keeps the values a rolled-back transaction used, so `serial_global` has gaps after a failed update. irrd-ng rolls the counter back with the transaction, so it has none. `serial_global` only appears in exports and the journal tables, and NRTM serving uses the per-source serials, which match.
- **P-16 One-line errors instead of tracebacks in the tools.** Where a v4 tool dies with a Python traceback, irrd-ng prints only the exception line or lines, without the stack frames. The exit code is the same. P-02 covers the same idea for configuration errors.
- **P-17 Schema tools on the embedded store.** `irrd_database_upgrade` and `irrd_database_downgrade` do not print alembic's own INFO lines (`Context impl PostgresqlImpl.` and similar). Downgrading to an older revision prints success and exits 0 but changes nothing, because the store has no alembic revisions.
- **P-18 `IRRD_NG_STORE_PATH`.** A new environment variable, defaulting to `/var/lib/irrd-ng`, sets where the store lives. There is deliberately no `irrd.yaml` key for it, so a v4 configuration stays valid for both.
- **P-19 Fixed order where v4 uses Python set order in loaders.** v4 lists unknown object classes, and applies the deletions in `irrd_update_database`, in Python set order, which changes between runs. irrd-ng lists unknown classes in first-seen order and deletes in key order.
- **P-20 Small faithfulness gaps in stored metadata.** `rpsl_objects.ip_size` is derived from `ip_first` and `ip_last` instead of being stored. `database_status.updated` is the transaction time, not the moment of the statement. Store log lines come from an `irrd_ng.store` logger, which v4 does not have.
