//! Text handling from `irrd/utils/text.py`, plus the way v4's file importers
//! read RPSL files.

use std::borrow::Cow;
use std::fmt::Write as _;

/// Decode bytes the way v4 opens RPSL files:
/// `open(path, encoding="utf-8", errors="backslashreplace")`, which also
/// applies Python's universal newline translation (`\r\n` and a lone `\r`
/// both become `\n`).
///
/// Every byte that is not part of valid UTF-8 becomes the four characters
/// `\xNN` (lower-case hex). A byte order mark is kept, as Python's `utf-8`
/// codec does.
pub fn decode_rpsl_file(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        push_universal_newlines(&mut out, chunk.valid());
        for b in chunk.invalid() {
            let _ = write!(out, "\\x{b:02x}");
        }
    }
    // A '\r' at the end of one valid chunk followed by '\n' at the start of
    // the next cannot happen: both are ASCII and never split a chunk.
    out
}

fn push_universal_newlines(out: &mut String, s: &str) {
    if !s.contains('\r') {
        out.push_str(s);
        return;
    }
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push('\n');
        } else {
            out.push(c);
        }
    }
}

/// Python's `str.strip()`: remove leading and trailing whitespace as CPython
/// defines it (Unicode `White_Space` plus U+001C to U+001F). v4 strips every
/// paragraph this way before parsing it.
pub fn py_strip(s: &str) -> &str {
    crate::py::strip(s)
}

/// `splitline_unicodesafe`: split on `\n` only (not on U+2028 and the other
/// characters Python's `str.splitlines` uses), after stripping leading and
/// trailing `\n`, and strip `\r` from both ends of every line.
pub fn splitline_unicodesafe(input: &str) -> impl Iterator<Item = &str> {
    let trimmed = input.trim_matches('\n');
    let empty = input.is_empty();
    trimmed
        .split('\n')
        .filter(move |_| !empty)
        .map(|line| line.trim_matches('\r'))
}

/// `split_paragraphs_rpsl(input, strip_comments)` for string input.
///
/// A paragraph ends only at a truly empty line; a line of spaces or tabs
/// stays inside its paragraph. Lines starting with `#` are always dropped,
/// and lines starting with `%` only when `strip_comments` is set, both
/// inside and between paragraphs.
///
/// v4 writes the comment test as
/// `strip_comments and line.startswith("%") or line.startswith("#")`, and
/// Python's operator precedence makes that `(strip_comments and %) or #`.
/// That is the behaviour wanted: `#` is an RPSL comment everywhere, while the
/// NRTMv3 caller (`strip_comments=False`) must keep `%START`/`%END`. See
/// "Not a divergence: comment line stripping" in `docs/divergences.md`.
///
/// Each paragraph is returned with every line terminated by `\n`.
pub fn split_paragraphs_rpsl(input: &str, strip_comments: bool) -> Vec<String> {
    let mut paragraphs = Vec::new();
    let mut current = String::new();
    for line in splitline_unicodesafe(input) {
        let line = line.trim_matches(['\r', '\n']);
        let is_comment = line.starts_with('#') || (strip_comments && line.starts_with('%'));
        if is_comment {
            continue;
        }
        if line.is_empty() {
            if !current.is_empty() {
                paragraphs.push(std::mem::take(&mut current));
            }
        } else {
            current.push_str(line);
            current.push('\n');
        }
    }
    if !crate::py::strip(&current).is_empty() {
        paragraphs.push(current);
    }
    paragraphs
}

/// Read RPSL file bytes as v4's file importers do: decode with
/// [`decode_rpsl_file`] and split with [`split_paragraphs_rpsl`]
/// (`strip_comments=True`).
pub fn split_rpsl_file(bytes: &[u8]) -> Vec<String> {
    let text = decode_rpsl_file(bytes);
    split_paragraphs_rpsl(&text, true)
}

/// `remove_auth_hashes` (`irrd/utils/text.py`): replace the hash after each
/// `CRYPT-PW`, `MD5-PW` or `BCRYPT-PW` (any case) up to the end of the line
/// with the dummy value.
pub fn remove_auth_hashes(input: &str) -> Cow<'_, str> {
    const SCHEMES: [&str; 3] = ["CRYPT-PW", "MD5-PW", "BCRYPT-PW"];
    let lower = input.to_ascii_lowercase();
    if !SCHEMES
        .iter()
        .any(|s| lower.contains(&s.to_ascii_lowercase()))
    {
        return Cow::Borrowed(input);
    }
    // re.compile(r"(CRYPT-PW|MD5-PW|BCRYPT-PW)[^\n]+", re.IGNORECASE)
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut last = 0;
    while i < bytes.len() {
        let matched = SCHEMES.iter().find(|s| {
            bytes.len() >= i + s.len() && bytes[i..i + s.len()].eq_ignore_ascii_case(s.as_bytes())
        });
        if let Some(scheme) = matched {
            let after = i + scheme.len();
            let end = input[after..].find('\n').map_or(input.len(), |p| after + p);
            if end > after {
                out.push_str(&input[last..after]);
                out.push(' ');
                out.push_str(crate::fields::PASSWORD_HASH_DUMMY_VALUE);
                out.push_str("  # Filtered for security");
                i = end;
                last = end;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&input[last..]);
    Cow::Owned(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn decodes_like_python() {
        assert_eq!(decode_rpsl_file(b"a\xffb\r\nc\rd"), "a\\xffb\nc\nd");
        assert_eq!(decode_rpsl_file(b"\xe2\x82A"), "\\xe2\\x82A");
    }

    #[test]
    fn splits_paragraphs_like_v4() {
        let input = "% c\nroute: x\n# c\n  \norigin: y\n\n\n%x\nperson: p\n";
        assert_eq!(
            split_paragraphs_rpsl(input, true),
            vec!["route: x\n  \norigin: y\n", "person: p\n"]
        );
        assert_eq!(
            split_paragraphs_rpsl(input, false),
            vec!["% c\nroute: x\n  \norigin: y\n", "%x\nperson: p\n"]
        );
    }

    #[test]
    fn splitline_matches_v4() {
        let v: Vec<&str> = splitline_unicodesafe("\n\ra\u{2028}b\r\nc\n\n").collect();
        assert_eq!(v, vec!["a\u{2028}b", "c"]);
        assert_eq!(splitline_unicodesafe("").count(), 0);
    }

    #[test]
    fn removes_auth_hashes() {
        assert_eq!(
            remove_auth_hashes("auth: md5-pw $1$abc\nx"),
            "auth: md5-pw DummyValue  # Filtered for security\nx"
        );
    }
}
