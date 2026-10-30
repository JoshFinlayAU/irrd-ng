# Divergences from IRRd v4

irrd-ng matches IRRd 4.5.4 byte for byte on every surface listed in CLAUDE.md. This file is the complete list of places where it deliberately does not. Anything that differs from v4 and is not listed here is a bug.

Each entry says what v4 does, what irrd-ng does instead, who can see the difference, and why. Entries are added only after review, never to make a failing parity diff pass.

## DIV-001: NRTMv4 keep_journal configuration error is formatted

- **v4** (`irrd/conf/__init__.py:477`): the string is missing its `f` prefix and repeats a word, so operators see `NRTMv4 server requires keep_journal to be set for for source {name}.` with a literal `{name}`.
- **irrd-ng**: `NRTMv4 server requires keep_journal to be set for source EXAMPLE.` with the real source name.
- **Visible to**: operators, in the configuration error list at startup or on SIGHUP. Not visible to clients.
- **Why**: a plain bug in v4. The fixed text names the source that needs fixing. Agreed with Josh, 2026-10-31.

## DIV-002: RPKI notify_invalid configuration error has its missing space

- **v4** (`irrd/conf/__init__.py:558`): two concatenated string literals with no space between them produce `...Set to true or false.DANGER: care is required...`.
- **irrd-ng**: `...Set to true or false. DANGER: care is required...`.
- **Visible to**: operators, in the configuration error list. Not visible to clients.
- **Why**: a plain bug in v4. Agreed with Josh, 2026-10-31.

## Not a divergence: comment line stripping

v4's `split_paragraphs_rpsl` (`irrd/utils/text.py:69`) has an operator precedence slip, `strip_comments and line.startswith("%") or line.startswith("#")`, so `#` lines are always dropped and `%` lines only when `strip_comments` is set. Read literally that looks like a bug, but the behaviour it produces is the right one: RPSL treats `#` lines as comments everywhere, while NRTMv3 streams (the one caller that passes `strip_comments=False`) must keep `%` lines for `%START` and `%END`. Correcting the precedence would make irrd-ng keep `#` lines in NRTMv3 streams, which would then reject any mirrored object containing a whole-line comment and any stream with a `#` line after `%END`. irrd-ng therefore implements v4's behaviour, written out explicitly, and produces identical results.
