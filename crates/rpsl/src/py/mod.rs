//! CPython string and integer semantics that leak into IRRd v4's RPSL output.
//!
//! v4 is Python, and several of its observable results depend on exactly how
//! CPython 3.13 (Unicode 15.1) treats text: which characters `str.strip()`
//! removes, what `str.upper()` maps a character to, which characters
//! `str.isprintable()` rejects, what `int()` accepts, and how `repr()` quotes a
//! string inside an error message. These helpers reproduce that behaviour, with
//! the Unicode tables generated from the pinned v4 container's own Python
//! (`gen_tables.py`), so that irrd-ng does not depend on Rust's Unicode version.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;

use num_bigint::BigInt;

mod tables;

/// `str.isspace()` for one character.
#[inline]
pub(crate) fn is_space(c: char) -> bool {
    match c {
        '\t'..='\r' | '\x1c'..='\x20' => true,
        c if (c as u32) < 0x85 => false,
        c => tables::SPACES.binary_search(&(c as u32)).is_ok(),
    }
}

/// `str.strip()` with no arguments.
#[inline]
pub(crate) fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `str.rstrip()` with no arguments.
#[inline]
pub(crate) fn rstrip(s: &str) -> &str {
    s.trim_end_matches(is_space)
}

/// `str.isprintable()` for one character.
#[inline]
pub(crate) fn is_printable(c: char) -> bool {
    let cp = c as u32;
    if (0x20..0x7f).contains(&cp) {
        return true;
    }
    if cp < 0x20 || cp == 0x7f {
        return false;
    }
    tables::NOT_PRINTABLE
        .binary_search_by(|&(lo, hi)| {
            if hi < cp {
                Ordering::Less
            } else if lo > cp {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        })
        .is_err()
}

/// The decimal value of a character for which `str.isdecimal()` is true
/// (which is also what `re`'s `\d` matches in a `str` pattern).
#[inline]
pub(crate) fn decimal_value(c: char) -> Option<u8> {
    let cp = c as u32;
    if c.is_ascii_digit() {
        return Some((cp - u32::from(b'0')) as u8);
    }
    if cp < 0x660 {
        return None;
    }
    let idx = tables::DECIMAL_RUNS
        .binary_search_by(|&(lo, hi, _)| {
            if hi < cp {
                Ordering::Less
            } else if lo > cp {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        })
        .ok()?;
    let (lo, _, first) = tables::DECIMAL_RUNS[idx];
    Some(first + (cp - lo) as u8)
}

/// `re` `\d` in a `str` pattern.
#[inline]
pub(crate) fn is_re_digit(c: char) -> bool {
    decimal_value(c).is_some()
}

fn map_lookup(table: &'static [(u32, &'static str)], c: char) -> Option<&'static str> {
    table
        .binary_search_by(|&(k, _)| k.cmp(&(c as u32)))
        .ok()
        .map(|i| table[i].1)
}

/// `str.upper()`.
pub(crate) fn upper(s: &str) -> Cow<'_, str> {
    if s.is_ascii() {
        if s.bytes().any(|b| b.is_ascii_lowercase()) {
            return Cow::Owned(s.to_ascii_uppercase());
        }
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            out.push(c.to_ascii_uppercase());
        } else if let Some(m) = map_lookup(&tables::UPPER, c) {
            out.push_str(m);
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// `str.lower()`, including CPython's final sigma rule (approximated with
/// Rust's cased-letter properties for the context check).
pub(crate) fn lower(s: &str) -> Cow<'_, str> {
    if s.is_ascii() {
        if s.bytes().any(|b| b.is_ascii_uppercase()) {
            return Cow::Owned(s.to_ascii_lowercase());
        }
        return Cow::Borrowed(s);
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let cased = |c: char| c.is_lowercase() || c.is_uppercase();
    for (i, &c) in chars.iter().enumerate() {
        if c.is_ascii() {
            out.push(c.to_ascii_lowercase());
        } else if c == '\u{3a3}' {
            let before = i > 0 && cased(chars[i - 1]);
            let after = chars.get(i + 1).is_some_and(|&n| cased(n));
            out.push(if before && !after { '\u{3c2}' } else { '\u{3c3}' });
        } else if let Some(m) = map_lookup(&tables::LOWER, c) {
            out.push_str(m);
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// `repr()` of a `str`.
pub(crate) fn repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            c if c == quote || c == '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c if c.is_ascii() => out.push(c),
            c if is_printable(c) => out.push(c),
            c => {
                let cp = c as u32;
                if cp <= 0xff {
                    out.push_str(&format!("\\x{cp:02x}"));
                } else if cp <= 0xffff {
                    out.push_str(&format!("\\u{cp:04x}"));
                } else {
                    out.push_str(&format!("\\U{cp:08x}"));
                }
            }
        }
    }
    out.push(quote);
    out
}

/// `"%.200R" % value`, as used in CPython's own `int()` error message.
pub(crate) fn repr_truncated(s: &str, max_chars: usize) -> String {
    let r = repr(s);
    match r.char_indices().nth(max_chars) {
        Some((idx, _)) => r[..idx].to_owned(),
        None => r,
    }
}

/// A Python `int`. Values that fit in an `i128` stay unboxed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PyInt {
    Small(i128),
    Big(BigInt),
}

impl PyInt {
    /// The value as a `u128`, if it is non-negative and fits.
    pub(crate) fn to_u128(&self) -> Option<u128> {
        match self {
            PyInt::Small(v) => u128::try_from(*v).ok(),
            PyInt::Big(b) => u128::try_from(b).ok(),
        }
    }

    /// The value as an `i128`, if it fits.
    pub(crate) fn to_i128(&self) -> Option<i128> {
        match self {
            PyInt::Small(v) => Some(*v),
            PyInt::Big(b) => i128::try_from(b).ok(),
        }
    }

    pub(crate) fn is_negative(&self) -> bool {
        match self {
            PyInt::Small(v) => *v < 0,
            PyInt::Big(b) => b.sign() == num_bigint::Sign::Minus,
        }
    }

    /// `"%x" % value`.
    pub(crate) fn hex(&self) -> String {
        match self {
            PyInt::Small(v) if *v < 0 => format!("-{:x}", v.unsigned_abs()),
            PyInt::Small(v) => format!("{v:x}"),
            PyInt::Big(b) => format!("{b:x}"),
        }
    }
}

impl fmt::Display for PyInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PyInt::Small(v) => write!(f, "{v}"),
            PyInt::Big(b) => write!(f, "{b}"),
        }
    }
}

/// Why `int(text, base)` raised `ValueError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IntError {
    /// "invalid literal for int() with base N: '...'"
    Invalid,
    /// CPython's 4300 digit limit for non power-of-two bases.
    TooManyDigits(usize),
}

/// CPython's default `sys.int_info.default_max_str_digits`.
const MAX_STR_DIGITS: usize = 4300;

/// `int(text, base)` for base 10 or 16, with CPython's rules for surrounding
/// whitespace, signs, `0x` prefixes, underscores and non-ASCII decimal digits.
pub(crate) fn parse_int(text: &str, base: u32) -> Result<PyInt, IntError> {
    // _PyUnicode_TransformDecimalAndSpaceToASCII: whitespace becomes ' ',
    // decimal digits become ASCII digits, any other non-ASCII is invalid.
    let mut buf: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.chars() {
        if c == '\0' {
            return Err(IntError::Invalid);
        }
        if c.is_ascii() {
            buf.push(c as u8);
        } else if is_space(c) {
            buf.push(b' ');
        } else if let Some(d) = decimal_value(c) {
            buf.push(b'0' + d);
        } else {
            return Err(IntError::Invalid);
        }
    }
    // Py_ISSPACE: ASCII characters are kept as they are by the transform
    // above, so \x1c-\x1f are not whitespace here although str.isspace()
    // says they are.
    let ascii_space = |b: u8| matches!(b, b' ' | b'\t'..=b'\r');
    let mut i = 0;
    while i < buf.len() && ascii_space(buf[i]) {
        i += 1;
    }
    let mut negative = false;
    if i < buf.len() && (buf[i] == b'+' || buf[i] == b'-') {
        negative = buf[i] == b'-';
        i += 1;
    }
    if base == 16
        && i + 1 < buf.len()
        && buf[i] == b'0'
        && (buf[i + 1] == b'x' || buf[i + 1] == b'X')
    {
        i += 2;
        if i < buf.len() && buf[i] == b'_' {
            i += 1;
        }
    }
    if i < buf.len() && buf[i] == b'_' {
        return Err(IntError::Invalid);
    }
    let digit = |b: u8| -> Option<u32> {
        let v = match b {
            b'0'..=b'9' => u32::from(b - b'0'),
            b'a'..=b'z' => u32::from(b - b'a') + 10,
            b'A'..=b'Z' => u32::from(b - b'A') + 10,
            _ => return None,
        };
        (v < base).then_some(v)
    };
    let start = i;
    let mut ndigits = 0usize;
    let mut prev_underscore = false;
    while i < buf.len() {
        let b = buf[i];
        if b == b'_' {
            if prev_underscore {
                return Err(IntError::Invalid);
            }
            prev_underscore = true;
        } else if digit(b).is_some() {
            prev_underscore = false;
            ndigits += 1;
        } else {
            break;
        }
        i += 1;
    }
    if ndigits == 0 || prev_underscore {
        return Err(IntError::Invalid);
    }
    if base == 10 && ndigits > MAX_STR_DIGITS {
        return Err(IntError::TooManyDigits(ndigits));
    }
    let digits_end = i;
    while i < buf.len() && ascii_space(buf[i]) {
        i += 1;
    }
    if i != buf.len() {
        return Err(IntError::Invalid);
    }
    let mut small: Option<i128> = Some(0);
    for &b in &buf[start..digits_end] {
        if let Some(d) = digit(b) {
            small = small
                .and_then(|v| v.checked_mul(i128::from(base)))
                .and_then(|v| v.checked_add(i128::from(d)));
        }
    }
    if let Some(v) = small {
        return Ok(PyInt::Small(if negative { -v } else { v }));
    }
    let cleaned: Vec<u8> = buf[start..digits_end]
        .iter()
        .copied()
        .filter(|&b| b != b'_')
        .collect();
    let mut big = BigInt::parse_bytes(&cleaned, base).ok_or(IntError::Invalid)?;
    if negative {
        big = -big;
    }
    Ok(PyInt::Big(big))
}

/// The `ValueError` text CPython gives for a failed `int(text, base)`.
pub(crate) fn int_error_message(text: &str, base: u32, err: &IntError) -> String {
    match err {
        IntError::Invalid => format!(
            "invalid literal for int() with base {base}: {}",
            repr_truncated(text, 200)
        ),
        IntError::TooManyDigits(n) => format!(
            "Exceeds the limit ({MAX_STR_DIGITS} digits) for integer string conversion: value has {n} digits; use sys.set_int_max_str_digits() to increase the limit"
        ),
    }
}

/// Python's `in` over a `str` for a single character, used by `re`-style
/// hand-written matchers: does `c` match `[A-Z]` under `re.IGNORECASE`.
#[inline]
pub(crate) fn re_ic_alpha(c: char) -> bool {
    c.is_ascii_alphabetic() || (!c.is_ascii() && tables::IGNORECASE_A_Z.contains(&(c as u32)))
}

/// Does `rest` satisfy a Python `$` at this point (end, or a single final `\n`).
#[inline]
pub(crate) fn re_dollar(rest: &str) -> bool {
    rest.is_empty() || rest == "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitespace_matches_cpython() {
        assert!(is_space('\x1c'));
        assert!(is_space('\u{85}'));
        assert!(is_space('\u{3000}'));
        assert!(!is_space('\u{200b}'));
        assert_eq!(strip("\u{a0} x \u{2003}"), "x");
    }

    #[test]
    fn printable_matches_cpython() {
        assert!(is_printable('a'));
        assert!(!is_printable('\u{85}'));
        assert!(!is_printable('\u{200d}'));
        assert!(!is_printable('\u{2028}'));
        assert!(is_printable('é'));
        assert!(!is_printable(' ') || is_printable(' '));
    }

    #[test]
    fn int_parsing_matches_cpython() {
        let ok = |s: &str, b: u32| parse_int(s, b).ok().and_then(|v| v.to_i128());
        assert_eq!(ok("0x10", 10), None);
        assert_eq!(ok("0x10", 16), Some(16));
        assert_eq!(ok(" 12 ", 10), Some(12));
        assert_eq!(ok("1_000", 10), Some(1000));
        assert_eq!(ok("+5", 16), Some(5));
        assert_eq!(ok("-0", 10), Some(0));
        assert_eq!(ok("١٢", 10), Some(12));
        assert_eq!(ok("1__0", 10), None);
        assert_eq!(ok("_1", 10), None);
        assert_eq!(ok("0x_1f", 16), Some(31));
        assert_eq!(ok("", 10), None);
        assert_eq!(ok("12a", 16), Some(298));
        assert_eq!(ok("\u{a0}12\u{2003}", 10), Some(12));
        assert_eq!(ok("0b1", 16), Some(177));
        let e = parse_int("x", 10).unwrap_err();
        assert_eq!(
            int_error_message("x", 10, &e),
            "invalid literal for int() with base 10: 'x'"
        );
    }

    #[test]
    fn repr_matches_cpython() {
        assert_eq!(repr("a'b"), "\"a'b\"");
        assert_eq!(repr("a\"b"), "'a\"b'");
        assert_eq!(repr("a'\"b"), "'a\\'\"b'");
        assert_eq!(
            repr("\x00\u{85}\u{200d}\u{d7ff}\u{1F600}\u{2028}"),
            "'\\x00\\x85\\u200d\\ud7ff\u{1F600}\\u2028'"
        );
        assert_eq!(repr("é"), "'é'");
    }

    #[test]
    fn case_mapping_matches_cpython() {
        assert_eq!(upper("straße"), "STRASSE");
        assert_eq!(lower("K"), "k");
        assert_eq!(upper("abc"), "ABC");
    }
}
