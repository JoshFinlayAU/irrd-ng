//! REST endpoints, GraphQL and the event stream.
//!
//! The routes of v4's Starlette app (`irrd/server/http/app.py`): `/`'s
//! redirect to `/ui/`, `/v1/status/`, `/v1/whois/`, `/graphql/`,
//! `/metrics/` and the event stream, with v4's status codes, headers and
//! middleware behaviour (Starlette's trusted host check, slash redirects
//! and 405s, uvicorn's proxy headers and `server` header, IRRd's security
//! headers). The web UI (`/ui/`) is a later phase.

#![deny(unsafe_code)]

mod event_stream;
pub use event_stream::Events;
mod gql;
pub mod messages;
mod pydantic;
mod sqltrace;
mod static_files;
mod status;
mod websocket;

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
    /// `server.whois.interface`, for `/v1/status/`.
    pub whois_interface: String,
    /// `server.whois.port`, for `/v1/status/`.
    pub whois_port: i64,
    /// `server.http.status_access_list` (`/v1/status/`, `/metrics/`).
    pub status_access_list: Option<String>,
    /// `server.http.event_stream_access_list`
    pub event_stream_access_list: Option<String>,
    /// NRTM settings of each source, for `/v1/status/`.
    pub status_sources: std::collections::HashMap<String, StatusSourceSettings>,
    /// Sources with `keep_journal` set, in configuration order: what the
    /// event stream reports as streamed.
    pub journaled_sources: Vec<String>,
    /// The host name, for the event stream's initial download
    /// (`socket.gethostname()`).
    pub hostname: String,
}

/// The NRTM settings of a source that `/v1/status/` reports.
#[derive(Debug, Clone, Default)]
pub struct StatusSourceSettings {
    /// `sources.<name>.nrtm_host`
    pub nrtm_host: Option<String>,
    /// `int(sources.<name>.nrtm_port)`, default 43.
    pub nrtm_port: i64,
    /// `sources.<name>.nrtm4_client_notification_file_url`
    pub nrtm4_client_notification_file_url: Option<String>,
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
    /// When the daemon started, in seconds since the epoch
    /// (`IRRD_MAIN_STARTUP_TIME`, for `/metrics/`).
    pub startup_time: i64,
    /// Store changes for the event stream: each source whose journal grew.
    pub events: event_stream::Events,
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

/// A response body: complete, or streamed in chunks. A complete body
/// never reports itself finished before it is polled. hyper treats a body
/// that is already at its end as "no body" and then drops a
/// `content-length: 0` header we set and appends its own after all the
/// others; with this wrapper our header stays where v4 sends it (straight
/// after `server`). hyper still takes the length from the exact size hint.
/// A streamed body has no length, so hyper sends it chunked, as uvicorn
/// does for Starlette's `StreamingResponse`.
#[derive(Debug)]
pub enum ReplyBody {
    /// The whole body.
    Full(Full<Bytes>),
    /// Chunks as they are produced.
    Stream(tokio::sync::mpsc::Receiver<Bytes>),
}

impl hyper::body::Body for ReplyBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
        match self.get_mut() {
            ReplyBody::Full(f) => std::pin::Pin::new(f).poll_frame(cx),
            ReplyBody::Stream(rx) => match rx.poll_recv(cx) {
                std::task::Poll::Ready(Some(b)) => {
                    std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(b))))
                }
                std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
                std::task::Poll::Pending => std::task::Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self {
            ReplyBody::Full(f) => f.size_hint(),
            ReplyBody::Stream(_) => hyper::body::SizeHint::default(),
        }
    }
}

/// A response being built, with headers in the order v4 sends them.
struct Reply {
    status: StatusCode,
    headers: Vec<(&'static str, String)>,
    body: Bytes,
    /// A streamed body instead of `body`.
    stream: Option<tokio::sync::mpsc::Receiver<Bytes>>,
    /// Inside the security header middleware (everything but the trusted
    /// host check).
    secured: bool,
    /// A WebSocket handshake to complete once the response is sent.
    upgrade: Option<websocket::Upgrade>,
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
            stream: None,
            secured: true,
            upgrade: None,
        }
    }

    fn with_type(status: StatusCode, content_type: &str, body: impl Into<Bytes>) -> Self {
        let mut r = Reply::text(status, body);
        r.headers[1].1 = content_type.to_owned();
        r
    }

    fn empty(status: StatusCode) -> Self {
        Reply {
            status,
            headers: Vec::new(),
            body: Bytes::new(),
            stream: None,
            secured: true,
            upgrade: None,
        }
    }

    fn redirect(status: StatusCode, location: String) -> Self {
        Reply {
            status,
            headers: vec![("content-length", "0".to_owned()), ("location", location)],
            body: Bytes::new(),
            stream: None,
            secured: true,
            upgrade: None,
        }
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
    path: &str,
) -> Response<ReplyBody> {
    let body = match reply.stream {
        Some(rx) if !head => ReplyBody::Stream(rx),
        _ => ReplyBody::Full(Full::new(if head { Bytes::new() } else { reply.body })),
    };
    let mut resp = Response::new(body);
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
        if path.starts_with("/static/") {
            put("cache-control", "no-cache");
        } else if session_cookie {
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

/// Starlette's `Router.redirect_slashes`: a 307 to the same URL with the
/// slash added, built from the `Host` header.
fn slash_redirect(headers: &HeaderMap, path: &str, raw_query: Option<&str>) -> Reply {
    let host_header = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let mut url = format!("http://{host_header}{path}/");
    if let Some(q) = raw_query {
        url.push('?');
        url.push_str(q);
    }
    Reply::redirect(StatusCode::TEMPORARY_REDIRECT, url)
}

/// The mounts of v4's app, by path prefix (matched with a slash added).
const MOUNTS: &[&str] = &["/v1/status", "/v1/whois", "/graphql", "/static", "/metrics"];

/// An access-listed endpoint's check (`is_client_permitted(host, ...)`).
fn permitted(state: &HttpState, host: &str, list: Option<&str>) -> bool {
    let q = state.query.read().map(|s| s.clone()).unwrap_or_default();
    q.is_client_permitted(host, list, true).unwrap_or(false)
}

/// What the route needs from the request.
struct Req<'a> {
    method: &'a Method,
    path: &'a str,
    raw_query: Option<&'a str>,
    headers: &'a HeaderMap,
    host: &'a str,
    port: u16,
}

async fn route(
    state: &Arc<HttpState>,
    settings: &HttpSettings,
    r: &Req<'_>,
    body: Option<Incoming>,
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Reply {
    let head = *r.method == Method::HEAD;
    let get = *r.method == Method::GET || head;
    let path = r.path;
    if path == "/" {
        return if get {
            Reply::redirect(StatusCode::FOUND, "/ui/".to_owned())
        } else {
            Reply::method_not_allowed("GET, HEAD")
        };
    }
    if let Some(m) = MOUNTS.iter().find(|m| path == **m) {
        return slash_redirect(r.headers, m, r.raw_query);
    }
    if path == "/v1/event-stream/initial" {
        return slash_redirect(r.headers, path, r.raw_query);
    }
    if path.starts_with("/v1/status/") {
        if !get {
            return Reply::method_not_allowed("GET");
        }
        if !permitted(state, r.host, settings.status_access_list.as_deref()) {
            return Reply::text(StatusCode::FORBIDDEN, messages::ACCESS_DENIED);
        }
        return status_endpoint(state, settings);
    }
    if path.starts_with("/v1/whois/") {
        return if get {
            whois_endpoint(state, r.host, r.port, r.raw_query)
        } else {
            Reply::method_not_allowed("GET")
        };
    }
    if path.starts_with("/graphql/") {
        let body = match body {
            Some(b) => http_body_util::BodyExt::collect(b)
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default(),
            None => Bytes::new(),
        };
        return graphql_endpoint(state, r, &body);
    }
    if path.starts_with("/static/") {
        return static_files::serve(r.method, path);
    }
    if path.starts_with("/metrics/") {
        if !get {
            return Reply::method_not_allowed("GET");
        }
        if !permitted(state, r.host, settings.status_access_list.as_deref()) {
            return Reply::text(StatusCode::FORBIDDEN, messages::ACCESS_DENIED);
        }
        return metrics_endpoint(state);
    }
    if path == "/v1/event-stream/" && websocket::is_upgrade(r.headers) {
        return websocket::accept(state.clone(), r.headers, r.host, on_upgrade, settings);
    }
    if path == "/v1/event-stream/initial/" {
        if !get {
            return Reply::method_not_allowed("GET");
        }
        if !permitted(state, r.host, settings.event_stream_access_list.as_deref()) {
            return Reply::text(StatusCode::FORBIDDEN, messages::ACCESS_DENIED);
        }
        return event_stream::initial_download(state.clone(), settings, r.host, r.raw_query);
    }
    Reply::text(StatusCode::NOT_FOUND, "Not Found")
}

fn status_endpoint(state: &HttpState, settings: &HttpSettings) -> Reply {
    let q = state.query.read().map(|s| s.clone()).unwrap_or_default();
    let text = tokio::task::block_in_place(|| -> store::Result<String> {
        let tx = state.store.read()?;
        status::status_text(&tx.view(), &q, settings)
    });
    match text {
        Ok(t) => Reply::text(StatusCode::OK, t),
        Err(e) => internal_server_error(&e.to_string()),
    }
}

fn metrics_endpoint(state: &HttpState) -> Reply {
    let q = state.query.read().map(|s| s.clone()).unwrap_or_default();
    let text = tokio::task::block_in_place(|| -> store::Result<String> {
        let tx = state.store.read()?;
        status::metrics_text(&tx.view(), &q, state.startup_time)
    });
    match text {
        Ok(t) => Reply::text(StatusCode::OK, t),
        Err(e) => internal_server_error(&e.to_string()),
    }
}

/// Starlette's `ServerErrorMiddleware` answer to an exception.
fn internal_server_error(log: &str) -> Reply {
    tracing::error!(target: ACCESS_LOG_TARGET, "{log}");
    let mut r = Reply::text(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error");
    r.secured = false;
    r
}

/// ariadne's `GraphQLHTTPHandler.handle_request()`.
fn graphql_endpoint(state: &HttpState, r: &Req<'_>, body: &[u8]) -> Reply {
    let allow = "OPTIONS, POST, GET";
    match *r.method {
        Method::GET => {
            return Reply::with_type(
                StatusCode::OK,
                "text/html; charset=utf-8",
                gql::GRAPHIQL_HTML,
            );
        }
        Method::POST => {}
        Method::OPTIONS => {
            let mut rep = Reply::empty(StatusCode::OK);
            rep.headers = vec![
                ("allow", allow.to_owned()),
                ("content-length", "0".to_owned()),
            ];
            return rep;
        }
        _ => {
            let mut rep = Reply::empty(StatusCode::METHOD_NOT_ALLOWED);
            rep.headers = vec![
                ("allow", allow.to_owned()),
                ("content-length", "0".to_owned()),
            ];
            return rep;
        }
    }
    let start = Instant::now();
    let content_type: String = r
        .headers
        .get("content-type")
        .map(|h| h.as_bytes().iter().map(|&b| b as char).collect())
        .unwrap_or_default();
    let ct = content_type.split(';').next().unwrap_or_default();
    let data = match ct {
        "application/json" => match ::graphql::value::json_loads(body) {
            Some(d) => d,
            None => {
                return Reply::text(StatusCode::BAD_REQUEST, messages::GRAPHQL_INVALID_JSON);
            }
        },
        "multipart/form-data" => {
            return Reply::text(StatusCode::BAD_REQUEST, messages::GRAPHQL_INVALID_MULTIPART);
        }
        _ => {
            return Reply::text(StatusCode::BAD_REQUEST, messages::GRAPHQL_CONTENT_TYPE);
        }
    };
    let settings = state.query.read().map(|s| s.clone()).unwrap_or_default();
    let outcome = tokio::task::block_in_place(|| -> store::Result<::graphql::Outcome> {
        let tx = state.store.read()?;
        let view = tx.view();
        let resolvers = gql::Resolvers {
            view: &view,
            settings: &settings,
            client_host: r.host.to_owned(),
            sql_trace: std::cell::RefCell::new(false),
            sql_queries: std::cell::RefCell::new(None),
        };
        let elapsed = || start.elapsed().as_secs_f64();
        Ok(::graphql::graphql(
            gql::schema(),
            &gql::IrrdScalars,
            &resolvers,
            &resolvers,
            &data,
            &elapsed,
        ))
    });
    match outcome {
        Ok(::graphql::Outcome::Result(success, result)) => {
            log_graphql_query(r.host, &data, &result);
            let status = if success
                || result
                    .get("data")
                    .is_some_and(|d| *d != ::graphql::Value::Null)
            {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            };
            Reply::with_type(
                status,
                "application/json",
                ::graphql::value::json_dumps(&result),
            )
        }
        Ok(::graphql::Outcome::Crash(e)) => internal_server_error(&e),
        Err(e) => internal_server_error(&e.to_string()),
    }
}

/// `QueryMetadataExtension.format()`'s log line.
fn log_graphql_query(host: &str, data: &::graphql::Value, result: &::graphql::Value) {
    let ::graphql::Value::Object(fields) = data else {
        return;
    };
    if data.get("operationName").and_then(::graphql::Value::as_str) == Some("IntrospectionQuery") {
        return;
    }
    let execution = result
        .get("extensions")
        .and_then(|e| e.get("execution"))
        .cloned()
        .unwrap_or(::graphql::Value::Null);
    let mut d = ::graphql::Value::Object(fields.clone());
    let q = match data.get("query") {
        Some(::graphql::Value::Str(s)) => s.clone(),
        Some(other) => ::graphql::value::inspect(other),
        None => String::new(),
    };
    d.set(
        "query",
        ::graphql::Value::Str(q.replace(' ', "").replace('\n', " ").replace('\t', "")),
    );
    let line = messages::graphql_query_log(
        host,
        &::graphql::value::inspect(&execution),
        &::graphql::value::inspect(&d),
    );
    let line: String = line.chars().take(5000).collect();
    tracing::info!(target: "irrd.server.graphql.extensions", "{line}");
}

async fn handle(
    state: Arc<HttpState>,
    peer: SocketAddr,
    mut req: Request<Incoming>,
) -> Result<Response<ReplyBody>, Infallible> {
    let start = Instant::now();
    let settings = state.http.read().map(|s| s.clone()).unwrap_or_default();
    let on_upgrade = if websocket::is_upgrade(req.headers()) {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };
    let (parts, body) = req.into_parts();
    let headers = &parts.headers;
    let (host, port) = client_of(peer, headers, &settings);
    let method = parts.method.clone();
    let head = method == Method::HEAD;
    let path = parts.uri.path().to_owned();
    let raw_query = parts.uri.query().map(str::to_owned);

    let reply = if !host_allowed(headers, settings.allowed_host.as_deref()) {
        let mut r = Reply::text(StatusCode::BAD_REQUEST, "Invalid host header");
        r.secured = false;
        r
    } else {
        let r = Req {
            method: &method,
            path: &path,
            raw_query: raw_query.as_deref(),
            headers,
            host: &host,
            port,
        };
        route(&state, &settings, &r, Some(body), on_upgrade).await
    };

    let cookie_name = if settings.https_only {
        "__Host-session"
    } else {
        "session"
    };
    let session_cookie = has_cookie(headers, cookie_name);
    let status = reply.status;
    let is_ws = reply.upgrade.is_some();
    let resp = if let Some(up) = reply.upgrade {
        websocket::response(up, &settings)
    } else {
        finish(reply, &settings, session_cookie, head, &path)
    };
    if !is_ws {
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
    }
    Ok(resp)
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
            // A WebSocket upgrade to the event stream is answered here, so
            // the 101 keeps uvicorn's header case; everything else, and
            // what was read so far, goes to hyper.
            let mut stream = stream;
            let mut head: Vec<u8> = Vec::new();
            const PREFIX: &[u8] = b"GET /v1/event-stream/ ";
            loop {
                let candidate = if head.len() < PREFIX.len() {
                    PREFIX.starts_with(&head)
                } else {
                    head.starts_with(PREFIX)
                };
                if !candidate || head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() > 65536 {
                    break;
                }
                let mut chunk = [0u8; 4096];
                match tokio::io::AsyncReadExt::read(&mut stream, &mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&chunk[..n]),
                }
            }
            if head.starts_with(PREFIX)
                && let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n")
            {
                match websocket::raw_handshake(state.clone(), stream, peer, &head[..end + 2]).await
                {
                    Ok(()) => return,
                    Err(s) => stream = s,
                }
            }
            let io = hyper_util::rt::TokioIo::new(Rewind::new(head, stream));
            let service = hyper::service::service_fn(move |req| handle(state.clone(), peer, req));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await;
        });
    }
}

/// A stream that first replays bytes already read from it.
struct Rewind<T> {
    pre: Vec<u8>,
    pos: usize,
    inner: T,
}

impl<T> Rewind<T> {
    fn new(pre: Vec<u8>, inner: T) -> Self {
        Rewind { pre, pos: 0, inner }
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Rewind<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        if me.pos < me.pre.len() {
            let n = (me.pre.len() - me.pos).min(buf.remaining());
            buf.put_slice(&me.pre[me.pos..me.pos + n]);
            me.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Rewind<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
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
