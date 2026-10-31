//! Python built-ins whose exact behaviour v4's output depends on, for the
//! other crates (the whois query parser strips, upper-cases and parses
//! integers exactly as CPython does).

use std::borrow::Cow;

/// `str.strip()`: CPython's whitespace definition.
pub fn strip(s: &str) -> &str {
    crate::py::strip(s)
}

/// `str.upper()`.
pub fn upper(s: &str) -> Cow<'_, str> {
    crate::py::upper(s)
}

/// `str.lower()`.
pub fn lower(s: &str) -> Cow<'_, str> {
    crate::py::lower(s)
}

/// `str.isspace()` for one character.
pub fn is_space(c: char) -> bool {
    crate::py::is_space(c)
}

/// `int(text)`: `None` where CPython raises `ValueError`. Values outside
/// the `i128` range saturate, which is enough for range checks.
pub fn int(text: &str) -> Option<i128> {
    let v = crate::py::parse_int(text, 10).ok()?;
    Some(v.to_i128().unwrap_or(if v.is_negative() {
        i128::MIN
    } else {
        i128::MAX
    }))
}

/// `repr()` of a `str`.
pub fn repr(s: &str) -> String {
    crate::py::repr(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_like_python() {
        assert_eq!(int(" 12 "), Some(12));
        assert_eq!(int("1_0"), Some(10));
        assert_eq!(int("+7"), Some(7));
        assert_eq!(int("x"), None);
        assert_eq!(int(""), None);
        assert_eq!(int("1".repeat(60).as_str()), Some(i128::MAX));
    }
}
