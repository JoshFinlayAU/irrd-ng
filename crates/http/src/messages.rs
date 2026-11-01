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

/// `PlainTextResponse("Access denied", status_code=403)`
pub const ACCESS_DENIED: &str = "Access denied";

/// ariadne's `HttpBadRequestError` for a body `json.loads` rejects.
pub const GRAPHQL_INVALID_JSON: &str = "Request body is not a valid JSON";

/// ariadne's `HttpBadRequestError` for a multipart body.
pub const GRAPHQL_INVALID_MULTIPART: &str = "Request body is not a valid multipart/form-data";

/// ariadne's `HttpBadRequestError` for any other content type.
pub const GRAPHQL_CONTENT_TYPE: &str =
    "Posted content must be of type application/json or multipart/form-data";

/// `resolve_rpsl_objects()`'s `ValueError` (shown to clients as
/// "Internal server error" by IRRd's error formatter).
pub const GRAPHQL_MORE_SPECIFIC: &str = "Your query must be more specific.";

/// `resolve_rpsl_object_journal()`
pub fn journal_denied(source: &str) -> String {
    format!("Access to journal denied for source {source}")
}

/// `QueryMetadataExtension.format()`'s log line (truncated to 5000
/// characters by the caller).
pub fn graphql_query_log(client: &str, execution: &str, query: &str) -> String {
    format!("{client} ran query in {execution}s: {query}")
}

/// `EventStreamInitialDownloadEndpoint`'s answer to unknown parameters.
pub fn unknown_get_parameters(names: &str) -> String {
    format!("Unknown GET parameters: {names}")
}

/// `AsyncEventStreamFollower.create()`'s answer to a serial beyond the
/// journal.
pub fn max_known_serial(serial: &str) -> String {
    format!("The maximum known serial is {serial}")
}

/// `EventStreamEndpoint.on_receive()`'s answer to a second subscription.
pub const STREAM_ALREADY_RUNNING: &str = "The stream is already running, request ignored.";
