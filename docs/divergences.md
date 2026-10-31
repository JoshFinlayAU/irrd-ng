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

## Not a divergence: comment line stripping

v4's `split_paragraphs_rpsl` (`irrd/utils/text.py:69`) has an operator precedence slip, `strip_comments and line.startswith("%") or line.startswith("#")`, so `#` lines are always dropped and `%` lines only when `strip_comments` is set. Read literally that looks like a bug, but the behaviour it produces is the right one: RPSL treats `#` lines as comments everywhere, while NRTMv3 streams (the one caller that passes `strip_comments=False`) must keep `%` lines for `%START` and `%END`. Correcting the precedence would make irrd-ng keep `#` lines in NRTMv3 streams, which would then reject any mirrored object containing a whole-line comment and any stream with a `#` line after `%END`. irrd-ng therefore implements v4's behaviour, written out explicitly, and produces identical results.

## Proposed, awaiting review

These are differences the Phase 1 work could not or did not close. None of them shows up on the fixture data from eight real registries or on the oracle corpora. Each needs a decision: accept it as a numbered divergence above, or keep it open as a bug to fix.

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
