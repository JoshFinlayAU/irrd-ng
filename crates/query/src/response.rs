//! A port of `WhoisQueryResponse` (`irrd/server/whois/query_response.py`):
//! response types, modes and the exact bytes of each.

use crate::messages;

/// `WhoisQueryResponseType`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseType {
    /// `SUCCESS`
    Success,
    /// `ERROR_INTERNAL`
    ErrorInternal,
    /// `ERROR_USER`
    ErrorUser,
    /// `KEY_NOT_FOUND`
    KeyNotFound,
    /// `NO_RESPONSE`
    NoResponse,
}

/// `WhoisQueryResponseMode`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    /// `IRRD`
    Irrd,
    /// `RIPE`
    Ripe,
}

/// A response; its text is the session's result buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response {
    /// The response type.
    pub response_type: ResponseType,
    /// The response mode.
    pub mode: ResponseMode,
    /// Whether `clean_response()` filters password hashes (not for `-g`).
    pub remove_auth_hashes: bool,
}

impl Response {
    pub(crate) fn new(response_type: ResponseType, mode: ResponseMode) -> Self {
        Response {
            response_type,
            mode,
            remove_auth_hashes: true,
        }
    }

    /// `clean_response()`: filter password hashes out of `result`.
    pub fn clean(&self, result: &mut String) {
        if !self.remove_auth_hashes || result.is_empty() {
            return;
        }
        if let std::borrow::Cow::Owned(cleaned) = rpsl::text::remove_auth_hashes(result) {
            *result = cleaned;
        }
    }

    /// `generate_response()` for a cleaned `result`, appended to `out`.
    /// An empty `result` is v4's `None` (both are falsy there).
    pub fn render(&self, result: &str, out: &mut Vec<u8>) {
        match self.mode {
            ResponseMode::Irrd => match self.response_type {
                ResponseType::Success => {
                    if result.is_empty() {
                        out.extend_from_slice(b"C\n");
                    } else {
                        out.push(b'A');
                        out.extend_from_slice((result.len() + 1).to_string().as_bytes());
                        out.push(b'\n');
                        out.extend_from_slice(result.as_bytes());
                        out.extend_from_slice(b"\nC\n");
                    }
                }
                ResponseType::KeyNotFound => out.extend_from_slice(b"D\n"),
                ResponseType::ErrorInternal | ResponseType::ErrorUser => {
                    out.extend_from_slice(b"F ");
                    out.extend_from_slice(result.as_bytes());
                    out.push(b'\n');
                }
                ResponseType::NoResponse => {}
            },
            ResponseMode::Ripe => match self.response_type {
                ResponseType::Success if !result.is_empty() => {
                    out.extend_from_slice(result.as_bytes());
                    out.extend_from_slice(b"\n\n\n");
                }
                ResponseType::Success | ResponseType::KeyNotFound => {
                    out.extend_from_slice(messages::RIPE_NO_ENTRIES.as_bytes())
                }
                ResponseType::ErrorInternal | ResponseType::ErrorUser => {
                    out.extend_from_slice(b"%% ERROR: ");
                    out.extend_from_slice(result.as_bytes());
                    out.extend_from_slice(b"\n\n\n");
                }
                // v4 raises RuntimeError here; the RIPE parser never
                // produces it.
                ResponseType::NoResponse => {}
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(t: ResponseType, m: ResponseMode, result: &str) -> Vec<u8> {
        let r = Response::new(t, m);
        let mut s = result.to_owned();
        r.clean(&mut s);
        let mut out = Vec::new();
        r.render(&s, &mut out);
        out
    }

    // irrd/server/whois/tests/test_query_response.py
    #[test]
    fn irrd_responses() {
        use ResponseMode::Irrd;
        use ResponseType::*;
        assert_eq!(render(Success, Irrd, "test"), b"A5\ntest\nC\n");
        assert_eq!(render(Success, Irrd, ""), b"C\n");
        assert_eq!(render(KeyNotFound, Irrd, ""), b"D\n");
        assert_eq!(render(ErrorInternal, Irrd, "test"), b"F test\n");
        assert_eq!(render(ErrorUser, Irrd, "test"), b"F test\n");
        assert_eq!(render(NoResponse, Irrd, ""), b"");
        // Length counts bytes of the UTF-8 encoding.
        assert_eq!(render(Success, Irrd, "é"), "A3\né\nC\n".as_bytes());
    }

    #[test]
    fn ripe_responses() {
        use ResponseMode::Ripe;
        use ResponseType::*;
        assert_eq!(render(Success, Ripe, "test"), b"test\n\n\n");
        assert_eq!(
            render(Success, Ripe, ""),
            b"%  No entries found for the selected source(s).\n\n\n"
        );
        assert_eq!(
            render(KeyNotFound, Ripe, ""),
            b"%  No entries found for the selected source(s).\n\n\n"
        );
        assert_eq!(render(ErrorInternal, Ripe, "test"), b"%% ERROR: test\n\n\n");
        assert_eq!(render(ErrorUser, Ripe, "test"), b"%% ERROR: test\n\n\n");
    }

    #[test]
    fn auth_hashes_removed() {
        let out = render(
            ResponseType::Success,
            ResponseMode::Ripe,
            "auth: CRYPT-Pw LEuuhsBJNFV0Q",
        );
        assert_eq!(
            out,
            b"auth: CRYPT-Pw DummyValue  # Filtered for security\n\n\n"
        );
    }
}
