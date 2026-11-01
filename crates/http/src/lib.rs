//! REST endpoints, GraphQL and the event stream.
//!
//! Phase 3 serves what the whois work needs: `/v1/whois/` over the same
//! engine as the whois server, and `/`'s redirect to `/ui/`, with v4's
//! status codes, headers and middleware behaviour (Starlette's trusted host
//! check, slash redirects and 405s, uvicorn's proxy headers and `server`
//! header, IRRd's security headers). Every other route answers 404 until
//! Phase 8.

#![deny(unsafe_code)]

pub mod messages;
mod submit;

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use query::{NrtmV3, QuerySettings, ResponseType, WhoisSession};
use store::Store;
use tokio::net::TcpListener;

/// Settings of the HTTP server itself.
#[derive(Debug, Clone, Default)]
pub struct HttpSettings {
    /// The `server` header: `IRRd 4.5.4`.
    pub server_header: String,
    /// The host name of `server.http.url`: Starlette's
    /// `TrustedHostMiddleware` refuses any other `Host`. `None` disables
    /// the check.
    pub allowed_host: Option<String>,
    /// `server.http.url` is `https://` (names the session cookie).
    pub https_only: bool,
    /// `server.http.forwarded_allowed_ips`, for uvicorn's proxy headers.
    pub forwarded_allowed_ips: Vec<String>,
}

/// Shared state: the store and the settings, replaced on SIGHUP.
pub struct HttpState {
    /// The store.
    pub store: Store,
    /// The whois engine's settings.
    pub query: RwLock<Arc<QuerySettings>>,
    /// The HTTP settings.
    pub http: RwLock<Arc<HttpSettings>>,
    /// NRTMv3 serving for `-g`.
    pub nrtm: Arc<dyn NrtmV3>,
    /// Settings for `/v1/submit/` and `/v1/suspension/`.
    pub submit: RwLock<Arc<auth::SubmitSettings>>,
}

impl std::fmt::Debug for HttpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpState").finish_non_exhaustive()
    }
}

const LOG_TARGET: &str = "irrd.server.http.endpoints_api";
const ACCESS_LOG_TARGET: &str = "irrd.server.http.app";

/// `CONTENT_SECURITY_POLICY` and the rest of `SECURITY_HEADERS`
/// (`irrd/server/http/app.py`), in v4's order.
const SECURITY_HEADERS: &[(&str, &str)] = &[
    (
        "content-security-policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    ),
    (
        "permissions-policy",
        "publickey-credentials-create=(self), publickey-credentials-get=(self), accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), otp-credentials=(), payment=(), picture-in-picture=(), screen-wake-lock=(), serial=(), usb=(), web-share=(), xr-spatial-tracking=()",
    ),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    ("origin-agent-cluster", "?1"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
    ("x-permitted-cross-domain-policies", "none"),
];

const TEXT_PLAIN: &str = "text/plain; charset=utf-8";

/// A complete response body that never reports itself finished before it
/// is polled. hyper treats a body that is already at its end as "no body"
/// and then drops a `content-length: 0` header we set and appends its own
/// after all the others; with this wrapper our header stays where v4 sends
/// it (straight after `server`). hyper still takes the length from the
/// exact size hint.
#[derive(Debug)]
pub struct ReplyBody(Full<Bytes>);

impl hyper::body::Body for ReplyBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.0.size_hint()
    }
}

/// A response being built, with headers in the order v4 sends them.
struct Reply {
    status: StatusCode,
    headers: Vec<(&'static str, String)>,
    body: Bytes,
    /// Inside the security header middleware (everything but the trusted
    /// host check).
    secured: bool,
}

impl Reply {
    fn text(status: StatusCode, body: impl Into<Bytes>) -> Self {
        let body = body.into();
        Reply {
            status,
            headers: vec![
                ("content-length", body.len().to_string()),
                ("content-type", TEXT_PLAIN.to_owned()),
            ],
            body,
            secured: true,
        }
    }

    fn empty(status: StatusCode) -> Self {
        Reply {
            status,
            headers: Vec::new(),
            body: Bytes::new(),
            secured: true,
        }
    }

    fn redirect(status: StatusCode, location: String) -> Self {
        Reply {
            status,
            headers: vec![("content-length", "0".to_owned()), ("location", location)],
            body: Bytes::new(),
            secured: true,
        }
    }

    fn json(body: String) -> Self {
        let body = Bytes::from(body);
        Reply {
            status: StatusCode::OK,
            headers: vec![
                ("content-length", body.len().to_string()),
                ("content-type", "application/json".to_owned()),
            ],
            body,
            secured: true,
        }
    }

    /// Starlette's `ServerErrorMiddleware` answer to an exception: outside
    /// every other middleware, so without the security headers.
    fn internal_error() -> Self {
        let mut r = Reply::text(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error");
        r.secured = false;
        r
    }

    fn method_not_allowed(allow: &str) -> Self {
        let mut r = Reply::text(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        r.headers.insert(0, ("allow", allow.to_owned()));
        r
    }
}

/// uvicorn's `_TrustedHosts`: addresses, networks or `*`.
fn trusted(list: &[String], host: &str) -> bool {
    if list.iter().any(|t| t == "*") {
        return true;
    }
    let ip: Option<IpAddr> = host.parse().ok();
    list.iter().any(|t| {
        if t == host {
            return true;
        }
        match (t.split_once('/'), ip) {
            (Some((net, len)), Some(ip)) => match (net.parse::<IpAddr>(), len.parse::<u32>()) {
                (Ok(IpAddr::V4(n)), Ok(l)) if l <= 32 => match ip {
                    IpAddr::V4(a) => {
                        let m = if l == 0 { 0 } else { u32::MAX << (32 - l) };
                        u32::from(a) & m == u32::from(n) & m
                    }
                    IpAddr::V6(_) => false,
                },
                (Ok(IpAddr::V6(n)), Ok(l)) if l <= 128 => match ip {
                    IpAddr::V6(a) => {
                        let m = if l == 0 { 0 } else { u128::MAX << (128 - l) };
                        u128::from(a) & m == u128::from(n) & m
                    }
                    IpAddr::V4(_) => false,
                },
                _ => false,
            },
            _ => false,
        }
    })
}

/// The client `(host, port)` as v4 sees it, after uvicorn's
/// `ProxyHeadersMiddleware`.
fn client_of(peer: SocketAddr, headers: &HeaderMap, settings: &HttpSettings) -> (String, u16) {
    let host = peer.ip().to_string();
    if trusted(&settings.forwarded_allowed_ips, &host)
        && let Some(xff) = headers.get("x-forwarded-for")
    {
        let raw: String = xff.as_bytes().iter().map(|&b| b as char).collect();
        let hosts: Vec<&str> = raw.split(',').map(str::trim).collect();
        let pick = if settings.forwarded_allowed_ips.iter().any(|t| t == "*") {
            hosts[0]
        } else {
            hosts
                .iter()
                .rev()
                .find(|h| !trusted(&settings.forwarded_allowed_ips, h))
                .copied()
                .unwrap_or(hosts[0])
        };
        if !pick.is_empty() {
            return (pick.to_owned(), 0);
        }
    }
    (host, peer.port())
}

/// Starlette's `QueryParams`: the raw query string as Latin-1, split on
/// `&`, `+` as space, percent escapes decoded as UTF-8 with replacement.
/// The last value of a repeated key wins.
fn query_param(raw: Option<&str>, key: &str) -> Option<String> {
    let raw = raw?;
    let mut found = None;
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if unquote_plus(k) == key {
            found = Some(unquote_plus(v));
        }
    }
    found
}

/// `urllib.parse.unquote_plus(s)` on a Latin-1 decoded string.
fn unquote_plus(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut pending: Vec<u8> = Vec::new();
    let mut i = 0;
    let flush = |pending: &mut Vec<u8>, out: &mut String| {
        if !pending.is_empty() {
            out.push_str(&String::from_utf8_lossy(pending));
            pending.clear();
        }
    };
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hex = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
            pending.push(hex(bytes[i + 1]) * 16 + hex(bytes[i + 2]));
            i += 3;
            continue;
        }
        if b.is_ascii() {
            pending.push(if b == b'+' { b' ' } else { b });
            i += 1;
            continue;
        }
        // Raw bytes beyond ASCII: hyper hands the query over as bytes;
        // Starlette decodes them as Latin-1.
        flush(&mut pending, &mut out);
        out.push(b as char);
        i += 1;
    }
    flush(&mut pending, &mut out);
    out
}

/// Starlette's `TrustedHostMiddleware` match.
fn host_allowed(headers: &HeaderMap, allowed: Option<&str>) -> bool {
    let Some(pattern) = allowed else {
        return true;
    };
    if pattern == "*" {
        return true;
    }
    let host_header: String = headers
        .get("host")
        .map(|h| h.as_bytes().iter().map(|&b| b as char).collect())
        .unwrap_or_default();
    let host = host_header.split(':').next().unwrap_or_default();
    host == pattern || (pattern.starts_with('*') && host.ends_with(&pattern[1..]))
}

fn has_cookie(headers: &HeaderMap, name: &str) -> bool {
    headers.get_all("cookie").iter().any(|v| {
        v.to_str().is_ok_and(|c| {
            c.split(';')
                .any(|kv| kv.split_once('=').is_some_and(|(k, _)| k.trim() == name))
        })
    })
}

fn finish(
    reply: Reply,
    settings: &HttpSettings,
    session_cookie: bool,
    head: bool,
) -> Response<ReplyBody> {
    let mut resp = Response::new(ReplyBody(Full::new(if head {
        Bytes::new()
    } else {
        reply.body
    })));
    *resp.status_mut() = reply.status;
    let h = resp.headers_mut();
    let mut put = |k: &str, v: &str| {
        if let (Ok(k), Ok(v)) = (HeaderName::try_from(k), HeaderValue::try_from(v)) {
            h.append(k, v);
        }
    };
    put(
        "date",
        &httpdate::fmt_http_date(std::time::SystemTime::now()),
    );
    put("server", &settings.server_header);
    for (k, v) in &reply.headers {
        put(k, v);
    }
    if reply.secured {
        put("vary", "Cookie");
        for (k, v) in SECURITY_HEADERS {
            put(k, v);
        }
        if session_cookie {
            put("cache-control", "no-store");
        }
    }
    resp
}

/// `WhoisQueryEndpoint.get()`
fn whois_endpoint(state: &HttpState, host: &str, port: u16, raw_query: Option<&str>) -> Reply {
    let start = Instant::now();
    let Some(q) = query_param(raw_query, "q") else {
        return Reply::text(StatusCode::BAD_REQUEST, query::messages::HTTP_MISSING_Q);
    };
    let client_str = format!("{host}:{port}");
    let settings = state.query.read().map(|s| s.clone()).unwrap_or_default();
    let mut session = WhoisSession::new(settings, state.nrtm.clone(), host, &client_str);
    let response = tokio::task::block_in_place(|| session.query_http(&state.store, &q));
    let result = session.result();
    tracing::info!(
        target: LOG_TARGET,
        "{}",
        query::messages::log_sent_http_answer(
            &client_str,
            start.elapsed().as_secs_f64(),
            result.chars().count(),
            &q
        )
    );
    match response.response_type {
        ResponseType::ErrorInternal => {
            Reply::text(StatusCode::INTERNAL_SERVER_ERROR, result.to_owned())
        }
        ResponseType::ErrorUser => Reply::text(StatusCode::BAD_REQUEST, result.to_owned()),
        _ if !result.is_empty() => Reply::text(StatusCode::OK, result.to_owned()),
        _ => Reply::empty(StatusCode::NO_CONTENT),
    }
}

async fn handle(
    state: Arc<HttpState>,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<ReplyBody>, Infallible> {
    let start = Instant::now();
    let settings = state.http.read().map(|s| s.clone()).unwrap_or_default();
    let (parts, body) = req.into_parts();
    let req = Request::from_parts(parts, ());
    let headers = req.headers();
    let (host, port) = client_of(peer, headers, &settings);
    let method = req.method().clone();
    let head = method == Method::HEAD;
    let path = req.uri().path().to_owned();
    let raw_query = req.uri().query().map(str::to_owned);

    let reply = if !host_allowed(headers, settings.allowed_host.as_deref()) {
        let mut r = Reply::text(StatusCode::BAD_REQUEST, "Invalid host header");
        r.secured = false;
        r
    } else if path == "/" {
        if method == Method::GET || head {
            Reply::redirect(StatusCode::FOUND, "/ui/".to_owned())
        } else {
            Reply::method_not_allowed("GET, HEAD")
        }
    } else if path == "/v1/whois" {
        // Router.redirect_slashes: the Mount matches with a slash added.
        let host_header = headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();
        let mut url = format!("http://{host_header}/v1/whois/");
        if let Some(q) = &raw_query {
            url.push('?');
            url.push_str(q);
        }
        Reply::redirect(StatusCode::TEMPORARY_REDIRECT, url)
    } else if path.starts_with("/v1/whois/") {
        if method == Method::GET || head {
            whois_endpoint(&state, &host, port, raw_query.as_deref())
        } else {
            Reply::method_not_allowed("GET")
        }
    } else if let Some(r) = submit_route(&state, &path, &method, headers, &host, body).await {
        r
    } else {
        Reply::text(StatusCode::NOT_FOUND, "Not Found")
    };

    let cookie_name = if settings.https_only {
        "__Host-session"
    } else {
        "session"
    };
    let session_cookie = has_cookie(headers, cookie_name);
    let status = reply.status;
    let resp = finish(reply, &settings, session_cookie, head);
    let request_line = match raw_query {
        Some(q) => format!("{method} {path}?{q} HTTP/1.1"),
        None => format!("{method} {path} HTTP/1.1"),
    };
    tracing::info!(
        target: ACCESS_LOG_TARGET,
        "{}",
        messages::access_log(
            &format!("{host}:{port}"),
            &request_line,
            status.as_u16(),
            status.canonical_reason().unwrap_or(""),
            start.elapsed().as_secs_f64()
        )
    );
    Ok(resp)
}

/// `/v1/submit/` and `/v1/suspension/`, or `None` for other paths.
async fn submit_route(
    state: &HttpState,
    path: &str,
    method: &Method,
    headers: &HeaderMap,
    host: &str,
    body: Incoming,
) -> Option<Reply> {
    let (mount, allow) = if path == "/v1/submit" || path.starts_with("/v1/submit/") {
        ("/v1/submit", "POST, DELETE")
    } else if path == "/v1/suspension" || path.starts_with("/v1/suspension/") {
        ("/v1/suspension", "POST")
    } else {
        return None;
    };
    if path == mount {
        // Router.redirect_slashes, as for /v1/whois.
        let host_header = headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();
        return Some(Reply::redirect(
            StatusCode::TEMPORARY_REDIRECT,
            format!("http://{host_header}{mount}/"),
        ));
    }
    let delete = *method == Method::DELETE;
    if !(*method == Method::POST || (delete && mount == "/v1/submit")) {
        return Some(Reply::method_not_allowed(allow));
    }
    use http_body_util::BodyExt;
    let Ok(collected) = body.collect().await else {
        return Some(Reply::internal_error());
    };
    let bytes = collected.to_bytes();
    let settings = state.submit.read().map(|s| s.clone()).unwrap_or_default();
    let reply = tokio::task::block_in_place(|| {
        if mount == "/v1/submit" {
            submit::submit(&state.store, settings, host, headers, &bytes, delete)
        } else {
            submit::suspension(&state.store, settings, host, headers, &bytes)
        }
    });
    Some(match reply {
        submit::SubmitReply::Json(j) => Reply::json(j),
        submit::SubmitReply::BadRequest(m) => Reply::text(StatusCode::BAD_REQUEST, m),
        submit::SubmitReply::Internal(e) => {
            tracing::error!(target: ACCESS_LOG_TARGET, "Exception in ASGI application: {e}");
            Reply::internal_error()
        }
    })
}

/// Serve HTTP on `listener` until the task is dropped.
pub async fn serve(listener: TcpListener, state: Arc<HttpState>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(target: ACCESS_LOG_TARGET, "{e}");
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(stream);
            let service = hyper::service::service_fn(move |req| handle(state.clone(), peer, req));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_strings_like_starlette() {
        assert_eq!(query_param(Some("q=!v"), "q").as_deref(), Some("!v"));
        assert_eq!(query_param(Some("q=!v&q=!x"), "q").as_deref(), Some("!x"));
        assert_eq!(
            query_param(Some("q=a+b%20c"), "q").as_deref(),
            Some("a b c")
        );
        assert_eq!(query_param(Some("q"), "q").as_deref(), Some(""));
        assert_eq!(query_param(Some("x=1"), "q"), None);
        assert_eq!(query_param(None, "q"), None);
        assert_eq!(
            query_param(Some("q=%E2%82"), "q").as_deref(),
            Some("\u{fffd}")
        );
        assert_eq!(query_param(Some("q=%C3%A9"), "q").as_deref(), Some("é"));
        assert_eq!(query_param(Some("q=%zz"), "q").as_deref(), Some("%zz"));
    }

    #[test]
    fn trusted_proxies() {
        let list = vec!["127.0.0.1".to_owned(), "10.0.0.0/8".to_owned()];
        assert!(trusted(&list, "127.0.0.1"));
        assert!(trusted(&list, "10.1.2.3"));
        assert!(!trusted(&list, "192.0.2.1"));
    }
}
