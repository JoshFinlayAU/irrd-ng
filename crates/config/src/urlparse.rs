//! Python 3.13's `urllib.parse.urlparse`, as far as v4's checks look at it:
//! the scheme, netloc and path, and the `ValueError`s it raises (which v4
//! does not catch).

use crate::python::{PyException, Value};

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ParseResult {
    pub(crate) scheme: String,
    pub(crate) netloc: String,
    pub(crate) path: String,
}

const C0_CONTROL_OR_SPACE: &[char] = &[
    '\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\t', '\n', '\x0b',
    '\x0c', '\r', '\x0e', '\x0f', '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17',
    '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', ' ',
];

const USES_PARAMS: &[&str] = &[
    "", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp", "rtsp", "rtsps", "rtspu",
    "sip", "sips", "mms", "sftp", "tel",
];

fn invalid_ipv6_url() -> PyException {
    PyException::value_error("Invalid IPv6 URL")
}

/// `urlparse(value)` for whatever v4 found in the config.
pub(crate) fn urlparse(value: Option<&Value>) -> Result<ParseResult, PyException> {
    let text = match value {
        None => String::new(),
        Some(Value::Str(s)) => s.clone(),
        Some(v) if !v.truthy() => String::new(),
        Some(Value::Bytes(b)) => match std::str::from_utf8(b) {
            Ok(s) if s.is_ascii() => s.to_owned(),
            _ => {
                return Err(PyException::new(
                    "UnicodeDecodeError",
                    "'ascii' codec can't decode bytes",
                ));
            }
        },
        Some(v) => return Err(PyException::attribute_error(v, "decode")),
    };
    urlparse_str(&text)
}

fn urlparse_str(url: &str) -> Result<ParseResult, PyException> {
    let mut url: String = url.trim_start_matches(C0_CONTROL_OR_SPACE).to_owned();
    url.retain(|c| !matches!(c, '\t' | '\r' | '\n'));
    let mut scheme = String::new();
    let mut netloc = String::new();
    if let Some(i) = url.find(':')
        && i > 0
    {
        let first = url.chars().next().unwrap_or(' ');
        if first.is_ascii_alphabetic()
            && url[..i]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            scheme = url[..i].to_lowercase();
            url = url[i + 1..].to_owned();
        }
    }
    if url.starts_with("//") {
        let rest = &url[2..];
        let delim = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        netloc = rest[..delim].to_owned();
        url = rest[delim..].to_owned();
        let open = netloc.contains('[');
        let close = netloc.contains(']');
        if open != close {
            return Err(invalid_ipv6_url());
        }
        if open && close {
            check_bracketed_netloc(&netloc)?;
        }
    }
    if let Some((before, _)) = url.split_once('#') {
        url = before.to_owned();
    }
    if let Some((before, _)) = url.split_once('?') {
        url = before.to_owned();
    }
    if USES_PARAMS.contains(&scheme.as_str()) && url.contains(';') {
        let cut = match url.rfind('/') {
            Some(slash) => url[slash..].find(';').map(|p| p + slash),
            None => url.find(';'),
        };
        if let Some(cut) = cut {
            url.truncate(cut);
        }
    }
    Ok(ParseResult {
        scheme,
        netloc,
        path: url,
    })
}

fn check_bracketed_netloc(netloc: &str) -> Result<(), PyException> {
    let hostname_and_port = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
    let hostname = match hostname_and_port.split_once('[') {
        Some((before, bracketed)) => {
            if !before.is_empty() {
                return Err(invalid_ipv6_url());
            }
            let (hostname, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            if !port.is_empty() && !port.starts_with(':') {
                return Err(invalid_ipv6_url());
            }
            hostname
        }
        None => hostname_and_port
            .split_once(':')
            .map_or(hostname_and_port, |(h, _)| h),
    };
    check_bracketed_host(hostname)
}

fn check_bracketed_host(hostname: &str) -> Result<(), PyException> {
    if hostname.starts_with(['v', 'V']) {
        let rest = &hostname[1..];
        let valid = rest.split_once('.').is_some_and(|(hex, tail)| {
            !hex.is_empty()
                && hex.chars().all(|c| c.is_ascii_hexdigit())
                && !tail.is_empty()
                && !tail.contains('\n')
        });
        if !valid {
            return Err(PyException::value_error("IPvFuture address is invalid"));
        }
        return Ok(());
    }
    if hostname.parse::<std::net::Ipv4Addr>().is_ok() {
        return Err(PyException::value_error(
            "An IPv4 address cannot be in brackets",
        ));
    }
    let without_scope = hostname.split_once('%').map_or(hostname, |(a, _)| a);
    if without_scope.parse::<std::net::Ipv6Addr>().is_ok() {
        return Ok(());
    }
    Err(PyException::value_error(format!(
        "{} does not appear to be an IPv4 or IPv6 address",
        crate::python::str_repr(hostname)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> ParseResult {
        urlparse_str(s).unwrap_or_default()
    }

    #[test]
    fn splits_like_python() {
        let r = p("https://example.com/path?q#f");
        assert_eq!(
            (r.scheme.as_str(), r.netloc.as_str(), r.path.as_str()),
            ("https", "example.com", "/path")
        );
        let r = p("file:///tmp/x");
        assert_eq!(
            (r.scheme.as_str(), r.netloc.as_str(), r.path.as_str()),
            ("file", "", "/tmp/x")
        );
        let r = p("HTTP://X");
        assert_eq!(r.scheme, "http");
        let r = p("\u{1f4a9}");
        assert_eq!((r.scheme.as_str(), r.netloc.as_str()), ("", ""));
        assert!(urlparse_str("https://[::1").is_err());
        assert!(urlparse_str("https://[::1]:80/").is_ok());
        assert!(urlparse_str("https://[1.2.3.4]/").is_err());
        assert!(urlparse(Some(&Value::int(0))).is_ok());
        assert!(urlparse(Some(&Value::int(1))).is_err());
    }
}
