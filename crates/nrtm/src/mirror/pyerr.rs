//! Exceptions as v4's mirroring code sees them.
//!
//! v4's runners sort what goes wrong by exception class: an `OSError` is
//! logged as "An error occurred", a `ValueError` inside the NRTMv4 client
//! becomes an `NRTM4ClientError`, and anything else is logged as "An
//! exception occurred" with a traceback. The text is `str(exception)`.

/// A Python exception: its class family and `str()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PyErr {
    /// `OSError` and its subclasses (including `requests` and `urllib`
    /// errors, `TimeoutError`, `socket.gaierror`).
    Os(String),
    /// `ValueError` and its subclasses (`UnicodeDecodeError`,
    /// `json.JSONDecodeError`, `pydantic.ValidationError` once converted).
    Value(String),
    /// `NRTM4ClientError` (a `ValueError`), with its own log line.
    Nrtm4(String),
    /// Any other exception (`KeyError`, `TypeError`, `StopIteration`, ...).
    Other(String),
}

impl PyErr {
    /// The exception's `str()`.
    pub fn message(&self) -> &str {
        match self {
            PyErr::Os(m) | PyErr::Value(m) | PyErr::Nrtm4(m) | PyErr::Other(m) => m,
        }
    }
}

impl std::fmt::Display for PyErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl From<store::StoreError> for PyErr {
    fn from(e: store::StoreError) -> Self {
        PyErr::Other(e.to_string())
    }
}

/// `str(OSError)` for an I/O error from the operating system:
/// `[Errno N] strerror`, plus `: 'filename'` when one is given.
pub fn os_error_text(e: &std::io::Error, filename: Option<&str>) -> String {
    if e.kind() == std::io::ErrorKind::TimedOut && e.raw_os_error().is_none() {
        return "timed out".to_owned();
    }
    let Some(code) = e.raw_os_error() else {
        return e.to_string();
    };
    let text = e.to_string();
    let strerror = text
        .strip_suffix(&format!(" (os error {code})"))
        .unwrap_or(&text);
    match filename {
        Some(f) => format!("[Errno {code}] {strerror}: {}", config::str_repr(f)),
        None => format!("[Errno {code}] {strerror}"),
    }
}

/// An `OSError` from an I/O error.
pub fn os_error(e: &std::io::Error, filename: Option<&str>) -> PyErr {
    PyErr::Os(os_error_text(e, filename))
}

/// Python's `int(text)` for a string: surrounding whitespace allowed, an
/// optional sign, digits with single underscores between them. The error
/// is `ValueError: invalid literal for int() with base 10: '...'`.
pub fn py_int(text: &str) -> Result<i64, PyErr> {
    let fail = || {
        PyErr::Value(format!(
            "invalid literal for int() with base 10: {}",
            config::str_repr(text)
        ))
    };
    let t = rpsl::text::py_strip(text);
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return Err(fail());
    }
    // int() accepts any Unicode decimal digit; NRTM serials are ASCII.
    let mut value: i64 = 0;
    for c in digits.chars() {
        if c == '_' {
            continue;
        }
        let d = c.to_digit(10).ok_or_else(fail)?;
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(i64::from(d)))
            .ok_or_else(fail)?;
    }
    Ok(if neg { -value } else { value })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_like_python() {
        assert_eq!(py_int(" 424242\n"), Ok(424242));
        assert_eq!(py_int("1_000"), Ok(1000));
        assert_eq!(py_int("-5"), Ok(-5));
        assert_eq!(
            py_int("abc"),
            Err(PyErr::Value(
                "invalid literal for int() with base 10: 'abc'".into()
            ))
        );
        assert!(py_int("").is_err());
        assert!(py_int("1__0").is_err());
    }

    #[test]
    fn os_errors_like_python() {
        let e = std::io::Error::from_raw_os_error(2);
        assert_eq!(
            os_error_text(&e, Some("/x")),
            "[Errno 2] No such file or directory: '/x'"
        );
        let e = std::io::Error::from_raw_os_error(111);
        assert_eq!(os_error_text(&e, None), "[Errno 111] Connection refused");
    }
}
