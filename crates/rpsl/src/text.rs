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

/// The `nrtm_dummified_*` settings of one source, as
/// `dummify_object_text()` reads them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DummifySettings {
    /// `get_nrtm_dummified_object_classes_for_source()`: the classes,
    /// stripped and lower case.
    pub object_classes: Vec<String>,
    /// `nrtm_dummified_attributes`, in file order, as `str(key)` and
    /// `str(value)`. Empty when unset or falsy.
    pub attributes: Vec<(String, String)>,
    /// `str(nrtm_dummified_remarks)` when it is truthy.
    pub remarks: Option<String>,
}

impl DummifySettings {
    /// Whether dummification can change anything at all.
    pub fn is_active(&self) -> bool {
        !self.object_classes.is_empty() && !self.attributes.is_empty()
    }
}

/// Whether `c` ends a line for Python's `str.splitlines()`.
fn is_py_line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r'
            | '\x0b'
            | '\x0c'
            | '\x1c'
            | '\x1d'
            | '\x1e'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// `str.splitlines(keepends)`.
pub fn py_splitlines(s: &str, keepends: bool) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut iter = s.char_indices().peekable();
    while let Some((i, c)) = iter.next() {
        if !is_py_line_break(c) {
            continue;
        }
        let mut end = i + c.len_utf8();
        if c == '\r'
            && let Some(&(_, '\n')) = iter.peek()
        {
            iter.next();
            end += 1;
        }
        out.push(if keepends {
            &s[start..end]
        } else {
            &s[start..i]
        });
        start = end;
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// `textwrap.indent(text, prefix)`: prefix every line that is not
/// whitespace only.
pub fn py_textwrap_indent(text: &str, prefix: &str) -> String {
    let mut out = String::with_capacity(text.len() + prefix.len());
    for line in py_splitlines(text, true) {
        if !crate::py::strip(line).is_empty() {
            out.push_str(prefix);
        }
        out.push_str(line);
    }
    out
}

/// `str.ljust(width)` for an attribute name.
fn ljust(out: &mut String, s: &str, width: usize) {
    out.push_str(s);
    for _ in s.chars().count()..width {
        out.push(' ');
    }
}

/// `dummify_object_text(rpsl_text, object_class, source, pk)`
/// (`irrd/utils/text.py`) with the source's settings already looked up.
///
/// Lines starting with `<key>:` for a configured key are replaced by the
/// key, padded to the attribute width, and the value (`%s` in the value
/// becomes the primary key). If that changed the text at all, the
/// configured remarks are appended. Note that v4 compares against the text
/// rebuilt from `splitlines()`, so an object without a final newline counts
/// as changed.
pub fn dummify_object_text<'a>(
    rpsl_text: &'a str,
    object_class: &str,
    pk: &str,
    settings: &DummifySettings,
) -> Cow<'a, str> {
    if rpsl_text.is_empty()
        || !settings.object_classes.iter().any(|c| c == object_class)
        || settings.attributes.is_empty()
    {
        return Cow::Borrowed(rpsl_text);
    }
    let width = crate::parser::RPSL_ATTRIBUTE_TEXT_WIDTH;
    let dummy_remarks = settings.remarks.as_ref().map(|r| {
        let mut prefix = String::new();
        ljust(&mut prefix, "remarks:", width);
        let mut s = crate::py::strip(&py_textwrap_indent(r, &prefix)).to_owned();
        s.push('\n');
        s
    });
    let mut lines: Vec<Cow<'_, str>> = py_splitlines(rpsl_text, false)
        .into_iter()
        .map(Cow::Borrowed)
        .collect();
    for line in &mut lines {
        for (key, value) in &settings.attributes {
            let starts = line
                .strip_prefix(key.as_str())
                .is_some_and(|rest| rest.starts_with(':'));
            if starts {
                let mut new = String::new();
                ljust(&mut new, &format!("{key}:"), width);
                if value.contains("%s") {
                    new.push_str(&value.replace("%s", pk));
                } else {
                    new.push_str(value);
                }
                *line = Cow::Owned(new);
            }
        }
    }
    let mut dummified = lines.join("\n");
    dummified.push('\n');
    if dummified != rpsl_text
        && let Some(remarks) = dummy_remarks
    {
        dummified.push_str(&remarks);
    }
    Cow::Owned(dummified)
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

    fn dummify_settings(
        classes: &[&str],
        attrs: &[(&str, &str)],
        remarks: Option<&str>,
    ) -> DummifySettings {
        DummifySettings {
            object_classes: classes.iter().map(|c| (*c).to_owned()).collect(),
            attributes: attrs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            remarks: remarks.map(str::to_owned),
        }
    }

    /// Outputs recorded from v4's `dummify_object_text` in the pinned image.
    #[test]
    fn dummify_like_v4() {
        let s = dummify_settings(
            &["person"],
            &[
                ("address", "Dummy address for %s"),
                ("phone", "+31205354444"),
                ("e-mail", "123"),
            ],
            Some("Dummified\n\n  second line\n"),
        );
        let text = "person:         P\naddress:        Street 1\naddress:        City\nphone:          +1 555\ne-mail:         x@y\nnic-hdl:        P1-TEST\nsource:         TEST\n";
        assert_eq!(
            dummify_object_text(text, "person", "P1-TEST", &s),
            "person:         P\naddress:        Dummy address for P1-TEST\naddress:        Dummy address for P1-TEST\nphone:          +31205354444\ne-mail:         123\nnic-hdl:        P1-TEST\nsource:         TEST\nremarks:        Dummified\n\nremarks:          second line\n"
        );
        // No final newline: v4 sees a change and appends the remarks.
        let s = dummify_settings(&["mntner"], &[("descr", "True")], Some("R"));
        assert_eq!(
            dummify_object_text("mntner:         M\nremarks:        x", "mntner", "M", &s),
            "mntner:         M\nremarks:        x\nremarks:        R\n"
        );
        // splitlines() breaks on U+2028 and normalises CRLF.
        let s = dummify_settings(&["mntner"], &[("descr", "d")], None);
        assert_eq!(
            dummify_object_text(
                "mntner:         M\ndescr: a\u{2028}descr: b\r\nsource: X\n",
                "mntner",
                "M",
                &s
            ),
            "mntner:         M\ndescr:          d\ndescr:          d\nsource: X\n"
        );
        let s = dummify_settings(
            &["role"],
            &[("a-very-long-attribute-name", "v %s %s"), ("descr", "x")],
            None,
        );
        assert_eq!(
            dummify_object_text(
                "role: R\na-very-long-attribute-name: q\ndescrx: y\ndescr:z\n",
                "role",
                "R",
                &s
            ),
            "role: R\na-very-long-attribute-name:v R R\ndescrx: y\ndescr:          x\n"
        );
        // Nothing changed: no remarks.
        let s = dummify_settings(&["role"], &[("descr", "x")], Some("R"));
        assert_eq!(
            dummify_object_text("role: R\nsource: X\n", "role", "R", &s),
            "role: R\nsource: X\n"
        );
        let s = dummify_settings(&["route"], &[("descr", "x")], None);
        assert_eq!(
            dummify_object_text("role: R\ndescr: X\n", "role", "R", &s),
            "role: R\ndescr: X\n"
        );
    }

    #[test]
    fn splitlines_like_python() {
        assert_eq!(
            py_splitlines("a\r\nb\rc\n\nd", false),
            ["a", "b", "c", "", "d"]
        );
        assert_eq!(py_splitlines("a\r\nb\n", true), ["a\r\n", "b\n"]);
        assert!(py_splitlines("", true).is_empty());
        assert_eq!(py_textwrap_indent("a\n \nb", "> "), "> a\n \n> b");
    }
}
