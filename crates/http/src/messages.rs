//! User-facing strings, copied verbatim from IRRd v4 at the pinned baseline.
//!
//! Every message a client, operator or mail recipient can see lives here, so a
//! parity fix to wording touches exactly one place.

/// The access log line of `asgi_logger.AccessLoggerMiddleware` with v4's
/// format, `%(client_addr)s - "%(request_line)s" %(status_code)s - %(L)ss`.
pub fn access_log(
    client: &str,
    request_line: &str,
    status: u16,
    reason: &str,
    secs: f64,
) -> String {
    format!("{client} - \"{request_line}\" {status} {reason} - {secs:.6}s")
}
