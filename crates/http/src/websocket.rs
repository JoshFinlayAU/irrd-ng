//! The WebSocket protocol (RFC 6455) for the event stream, as uvicorn's
//! `websockets` implementation speaks it: the handshake response, with
//! `permessage-deflate` (RFC 7692) when the client offers it, text frames,
//! pings and the close handshake.

use std::sync::Arc;

use bytes::Bytes;
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
use http_body_util::Full;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{HeaderMap, Response, StatusCode};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::event_stream::{self, Subscribe};
use crate::{HttpSettings, HttpState, Reply, ReplyBody};

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// `ws_ping_interval` and `ws_ping_timeout`.
const PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// `WS_1008_POLICY_VIOLATION`
const CLOSE_POLICY: u16 = 1008;
/// `WS_1003_UNSUPPORTED_DATA`
const CLOSE_UNSUPPORTED: u16 = 1003;

/// A handshake to finish once hyper has sent the 101.
pub(crate) struct Upgrade {
    accept: String,
    deflate: Option<Deflate>,
    /// The `Sec-WebSocket-Protocol` the application accepted with.
    protocol: Option<&'static str>,
}

/// What a WebSocket upgrade reaches in v4's app.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Endpoint {
    /// `EventStreamEndpoint` at `/v1/event-stream/`.
    EventStream,
    /// ariadne's `GraphQLWSHandler`, anywhere under the `/graphql` mount.
    GraphQL,
    /// A mount of an `HTTPEndpoint` or `StaticFiles`, which asserts an
    /// HTTP scope: an exception before the handshake, so a 500.
    ServerError,
    /// Anything else: Starlette's router closes the connection before
    /// accepting it, which uvicorn answers with a 403.
    Forbidden,
}

/// The endpoint for a (percent-decoded) request path.
pub(crate) fn endpoint(path: &str) -> Endpoint {
    const HTTP_MOUNTS: &[&str] = &[
        "/v1/status/",
        "/v1/whois/",
        "/v1/submit/",
        "/v1/suspension/",
        "/metrics/",
        "/static/",
    ];
    if path == "/v1/event-stream/" {
        Endpoint::EventStream
    } else if path.starts_with("/graphql/") {
        Endpoint::GraphQL
    } else if HTTP_MOUNTS.iter().any(|m| path.starts_with(m)) {
        Endpoint::ServerError
    } else {
        Endpoint::Forbidden
    }
}

/// The subprotocol an endpoint accepts with: ariadne always accepts
/// with `graphql-ws`, whatever the client offered.
fn protocol_for(endpoint: Endpoint) -> Option<&'static str> {
    (endpoint == Endpoint::GraphQL).then_some("graphql-ws")
}

impl std::fmt::Debug for Upgrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upgrade").finish_non_exhaustive()
    }
}

/// Negotiated `permessage-deflate` parameters.
#[derive(Debug, Clone, Default)]
struct Deflate {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: Option<u8>,
    client_max_window_bits: Option<u8>,
    /// The `Sec-WebSocket-Extensions` response value.
    response: String,
}

fn header(headers: &HeaderMap, name: &str) -> String {
    headers
        .get_all(name)
        .iter()
        .map(|v| v.as_bytes().iter().map(|&b| b as char).collect::<String>())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether uvicorn would hand this request to the WebSocket protocol.
pub(crate) fn is_upgrade(headers: &HeaderMap) -> bool {
    header(headers, "upgrade").eq_ignore_ascii_case("websocket")
        && header(headers, "connection")
            .split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
}

/// The first `permessage-deflate` offer the server can accept.
fn negotiate(offers: &str) -> Option<Deflate> {
    for offer in offers.split(',') {
        let mut parts = offer.split(';').map(str::trim);
        if parts.next() != Some("permessage-deflate") {
            continue;
        }
        let mut d = Deflate::default();
        let mut resp = vec!["permessage-deflate".to_owned()];
        let mut ok = true;
        for p in parts {
            let (k, v) = p.split_once('=').map_or((p, None), |(k, v)| {
                (k.trim(), Some(v.trim().trim_matches('"')))
            });
            match k {
                "server_no_context_takeover" if v.is_none() => {
                    d.server_no_context_takeover = true;
                    resp.push("server_no_context_takeover".into());
                }
                "client_no_context_takeover" if v.is_none() => {
                    d.client_no_context_takeover = true;
                    resp.push("client_no_context_takeover".into());
                }
                "server_max_window_bits" => match v.and_then(|x| x.parse::<u8>().ok()) {
                    Some(b) if (8..=15).contains(&b) => {
                        d.server_max_window_bits = Some(b);
                        resp.push(format!("server_max_window_bits={b}"));
                    }
                    _ => ok = false,
                },
                "client_max_window_bits" => match v {
                    None => {}
                    Some(x) => match x.parse::<u8>() {
                        Ok(b) if (8..=15).contains(&b) => d.client_max_window_bits = Some(b),
                        _ => ok = false,
                    },
                },
                _ => ok = false,
            }
        }
        if ok {
            d.response = resp.join("; ");
            return Some(d);
        }
    }
    None
}

/// Accept the handshake and start the session once the connection is
/// upgraded.
pub(crate) fn accept(
    state: Arc<HttpState>,
    headers: &HeaderMap,
    host: &str,
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    settings: &HttpSettings,
    endpoint: Endpoint,
) -> Reply {
    let Some(mut up) = handshake(headers) else {
        let mut r = Reply::text(
            StatusCode::BAD_REQUEST,
            "Failed to open a WebSocket connection: invalid Sec-WebSocket-Key header.\n",
        );
        r.secured = false;
        return r;
    };
    up.protocol = protocol_for(endpoint);
    let deflate = up.deflate.clone();
    if let Some(on) = on_upgrade {
        let host = host.to_owned();
        let settings = settings.clone();
        tokio::spawn(async move {
            if let Ok(io) = on.await {
                let io = hyper_util::rt::TokioIo::new(io);
                if endpoint == Endpoint::GraphQL {
                    graphql_session(io, deflate).await;
                } else {
                    session(state, io, deflate, host, settings).await;
                }
            }
        });
    }
    let mut r = Reply::empty(StatusCode::SWITCHING_PROTOCOLS);
    r.upgrade = Some(up);
    r
}

/// The 101 response as uvicorn writes it, header case included (hyper
/// would lower-case the names).
fn raw_response(up: &Upgrade, settings: &HttpSettings) -> String {
    let mut s = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n",
        up.accept
    );
    if let Some(d) = &up.deflate {
        s.push_str(&format!("Sec-WebSocket-Extensions: {}\r\n", d.response));
    }
    if let Some(p) = up.protocol {
        s.push_str(&format!("Sec-WebSocket-Protocol: {p}\r\n"));
    }
    s.push_str(&format!(
        "date: {}\r\nserver: {}\r\n\r\n",
        httpdate::fmt_http_date(std::time::SystemTime::now()),
        settings.server_header
    ));
    s
}

/// A WebSocket handshake on a fresh connection, before hyper sees it:
/// `head` is the request head as read. `Err` hands the connection to
/// hyper (anything that is not a valid upgrade request from an allowed
/// host).
pub(crate) async fn raw_handshake(
    state: Arc<HttpState>,
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    head: &[u8],
) -> Result<(), tokio::net::TcpStream> {
    let text: String = head.iter().map(|&b| b as char).collect();
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let Some(target) = request_line
        .strip_prefix("GET ")
        .and_then(|r| r.strip_suffix(" HTTP/1.1"))
    else {
        return Err(stream);
    };
    let path = percent_decode(target.split('?').next().unwrap_or_default());
    let mut headers = HeaderMap::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        let Some((k, v)) = l.split_once(':') else {
            return Err(stream);
        };
        match (
            HeaderName::try_from(k.trim()),
            HeaderValue::try_from(v.trim()),
        ) {
            (Ok(k), Ok(v)) => {
                headers.append(k, v);
            }
            _ => return Err(stream),
        }
    }
    let settings = state.http.read().map(|s| s.clone()).unwrap_or_default();
    if !is_upgrade(&headers) || !crate::host_allowed(&headers, settings.allowed_host.as_deref()) {
        return Err(stream);
    }
    let Some(mut up) = handshake(&headers) else {
        return Err(stream);
    };
    let endpoint = endpoint(&path);
    match endpoint {
        Endpoint::Forbidden => {
            let resp = format!(
                "HTTP/1.1 403 Forbidden\r\nDate: {}\r\nContent-Length: 0\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
                httpdate::fmt_http_date(std::time::SystemTime::now())
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
            return Ok(());
        }
        Endpoint::ServerError => {
            tracing::error!(target: "uvicorn.error", "Exception in ASGI application\nAssertionError");
            let _ = stream.write_all(UVICORN_500).await;
            let _ = stream.shutdown().await;
            return Ok(());
        }
        Endpoint::EventStream | Endpoint::GraphQL => {}
    }
    up.protocol = protocol_for(endpoint);
    let (host, _) = crate::client_of(peer, &headers, &settings);
    if stream
        .write_all(raw_response(&up, &settings).as_bytes())
        .await
        .is_err()
    {
        return Ok(());
    }
    if endpoint == Endpoint::GraphQL {
        graphql_session(stream, up.deflate).await;
    } else {
        session(state, stream, up.deflate, host, (*settings).clone()).await;
    }
    Ok(())
}

/// uvicorn's `send_500_response()`.
const UVICORN_500: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 21\r\nconnection: close\r\n\r\nInternal Server Error";

/// `urllib.parse.unquote()`, as uvicorn derives the scope's `path`.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(x), Some(y)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push((x * 16 + y) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether websockets accepts the handshake headers.
pub(crate) fn handshake_ok(headers: &HeaderMap) -> bool {
    handshake(headers).is_some()
}

/// The accept key and negotiated compression, or `None` for a request
/// the server rejects.
fn handshake(headers: &HeaderMap) -> Option<Upgrade> {
    let key = header(headers, "sec-websocket-key");
    let version = header(headers, "sec-websocket-version");
    let key_ok = base64_decode(key.trim()).is_some_and(|k| k.len() == 16);
    if !key_ok || version.trim() != "13" {
        return None;
    }
    let mut h = Sha1::new();
    h.update(key.trim().as_bytes());
    h.update(GUID.as_bytes());
    Some(Upgrade {
        accept: base64_encode(&h.finalize()),
        deflate: negotiate(&header(headers, "sec-websocket-extensions")),
        protocol: None,
    })
}

/// The 101 response, headers in uvicorn's order.
pub(crate) fn response(up: Upgrade, settings: &HttpSettings) -> Response<ReplyBody> {
    let mut resp = Response::new(ReplyBody::Full(Full::new(Bytes::new())));
    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let h = resp.headers_mut();
    let mut put = |k: &str, v: &str| {
        if let (Ok(k), Ok(v)) = (HeaderName::try_from(k), HeaderValue::try_from(v)) {
            h.append(k, v);
        }
    };
    put("upgrade", "websocket");
    put("connection", "Upgrade");
    put("sec-websocket-accept", &up.accept);
    if let Some(d) = &up.deflate {
        put("sec-websocket-extensions", &d.response);
    }
    if let Some(p) = up.protocol {
        put("sec-websocket-protocol", p);
    }
    put(
        "date",
        &httpdate::fmt_http_date(std::time::SystemTime::now()),
    );
    put("server", &settings.server_header);
    resp
}

// ---- frames ----

struct Conn<IO> {
    io: IO,
    deflate: Option<Deflate>,
    compress: Option<Compress>,
    decompress: Option<Decompress>,
}

enum Frame {
    Text(String),
    Binary,
    Ping(Vec<u8>),
    Pong,
    /// A close frame: the payload of the close frame to answer with.
    Close(Vec<u8>),
}

/// The close frame websockets answers a client's close frame with: the
/// same code and reason, nothing for an empty frame, or its own error
/// for one it cannot parse (`Close.parse()` and `Close.check()`).
fn close_reply(payload: &[u8]) -> Vec<u8> {
    const EXTERNAL: &[u16] = &[
        1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014,
    ];
    match payload.len() {
        0 => Vec::new(),
        1 => 1002u16.to_be_bytes().to_vec(),
        _ => {
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            if std::str::from_utf8(&payload[2..]).is_err() {
                1007u16.to_be_bytes().to_vec()
            } else if !(EXTERNAL.contains(&code) || (3000..5000).contains(&code)) {
                1002u16.to_be_bytes().to_vec()
            } else {
                payload.to_vec()
            }
        }
    }
}

impl<IO> Conn<IO> {
    fn new(io: IO, deflate: Option<Deflate>) -> Self {
        let compress = deflate.as_ref().map(|d| {
            Compress::new_with_window_bits(
                Compression::default(),
                false,
                d.server_max_window_bits.unwrap_or(15),
            )
        });
        let decompress = deflate.as_ref().map(|d| {
            Decompress::new_with_window_bits(false, d.client_max_window_bits.unwrap_or(15))
        });
        Conn {
            io,
            deflate,
            compress,
            decompress,
        }
    }
}

impl<IO: AsyncWrite + Unpin> Conn<IO> {
    async fn write_frame(&mut self, opcode: u8, rsv1: bool, payload: &[u8]) -> std::io::Result<()> {
        let mut head = vec![0x80 | opcode | if rsv1 { 0x40 } else { 0 }];
        let n = payload.len();
        if n < 126 {
            head.push(n as u8);
        } else if n <= 0xffff {
            head.push(126);
            head.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            head.push(127);
            head.extend_from_slice(&(n as u64).to_be_bytes());
        }
        head.extend_from_slice(payload);
        self.io.write_all(&head).await?;
        self.io.flush().await
    }

    async fn send_text(&mut self, text: &str) -> std::io::Result<()> {
        if let Some(c) = self.compress.as_mut() {
            if self
                .deflate
                .as_ref()
                .is_some_and(|d| d.server_no_context_takeover)
            {
                c.reset();
            }
            let mut out = Vec::with_capacity(text.len() / 2 + 64);
            let mut input = text.as_bytes();
            loop {
                let before_in = c.total_in();
                out.reserve(text.len() / 2 + 1024);
                c.compress_vec(input, &mut out, FlushCompress::Sync)
                    .map_err(std::io::Error::other)?;
                let used = (c.total_in() - before_in) as usize;
                input = &input[used..];
                if input.is_empty() && out.len() < out.capacity() {
                    break;
                }
            }
            if out.ends_with(&[0, 0, 0xff, 0xff]) {
                out.truncate(out.len() - 4);
            }
            return self.write_frame(0x1, true, &out).await;
        }
        self.write_frame(0x1, false, text.as_bytes()).await
    }

    async fn close(&mut self, code: u16) -> std::io::Result<()> {
        self.write_frame(0x8, false, &code.to_be_bytes()).await
    }
}

impl<IO: AsyncRead + Unpin> Conn<IO> {
    /// One complete message (reassembling fragments).
    async fn read_message(&mut self) -> std::io::Result<Frame> {
        let mut message: Vec<u8> = Vec::new();
        let mut compressed = false;
        let mut opcode0: Option<u8> = None;
        loop {
            let mut h = [0u8; 2];
            self.io.read_exact(&mut h).await?;
            let fin = h[0] & 0x80 != 0;
            let rsv1 = h[0] & 0x40 != 0;
            let opcode = h[0] & 0x0f;
            let masked = h[1] & 0x80 != 0;
            let mut len = u64::from(h[1] & 0x7f);
            if len == 126 {
                let mut b = [0u8; 2];
                self.io.read_exact(&mut b).await?;
                len = u64::from(u16::from_be_bytes(b));
            } else if len == 127 {
                let mut b = [0u8; 8];
                self.io.read_exact(&mut b).await?;
                len = u64::from_be_bytes(b);
            }
            if len > 64 * 1024 * 1024 {
                return Err(std::io::Error::other("frame too large"));
            }
            let mut mask = [0u8; 4];
            if masked {
                self.io.read_exact(&mut mask).await?;
            }
            let mut payload = vec![0u8; len as usize];
            self.io.read_exact(&mut payload).await?;
            if masked {
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= mask[i % 4];
                }
            }
            match opcode {
                0x8 => return Ok(Frame::Close(close_reply(&payload))),
                0x9 => return Ok(Frame::Ping(payload)),
                0xA => return Ok(Frame::Pong),
                0x0..=0x2 => {
                    if opcode != 0 {
                        opcode0 = Some(opcode);
                        compressed = rsv1;
                    }
                    message.extend_from_slice(&payload);
                    if fin {
                        break;
                    }
                }
                _ => return Err(std::io::Error::other("bad opcode")),
            }
        }
        if compressed {
            let Some(d) = self.decompress.as_mut() else {
                return Err(std::io::Error::other("unexpected compression"));
            };
            if self
                .deflate
                .as_ref()
                .is_some_and(|x| x.client_no_context_takeover)
            {
                d.reset(false);
            }
            message.extend_from_slice(&[0, 0, 0xff, 0xff]);
            let mut out = Vec::with_capacity(message.len() * 4 + 64);
            let mut input: &[u8] = &message;
            loop {
                let before = d.total_in();
                out.reserve(message.len() * 2 + 1024);
                d.decompress_vec(input, &mut out, FlushDecompress::Sync)
                    .map_err(std::io::Error::other)?;
                let used = (d.total_in() - before) as usize;
                input = &input[used..];
                if input.is_empty() {
                    break;
                }
            }
            message = out;
        }
        match opcode0 {
            Some(0x1) => Ok(Frame::Text(String::from_utf8_lossy(&message).into_owned())),
            _ => Ok(Frame::Binary),
        }
    }
}

/// `EventStreamEndpoint`: accept, check the access list, send the
/// header, then handle subscription requests while a follower streams.
async fn session<IO>(
    state: Arc<HttpState>,
    io: IO,
    deflate: Option<Deflate>,
    host: String,
    settings: HttpSettings,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (rd, wr) = tokio::io::split(io);
    let mut reader = Conn::new(rd, deflate.clone());
    let mut writer = Conn::new(wr, deflate);
    let q = state.query.read().map(|s| s.clone()).unwrap_or_default();
    let permitted = q
        .is_client_permitted(&host, settings.event_stream_access_list.as_deref(), true)
        .unwrap_or(false);
    if !permitted {
        let _ = writer.close(CLOSE_POLICY).await;
        return;
    }
    let header =
        match tokio::task::block_in_place(|| event_stream::stream_status(&state, &settings)) {
            Ok(h) => h,
            Err(_) => return,
        };
    if writer.send_text(&header).await.is_err() {
        return;
    }
    let (out_tx, writer_task, pinger) = spawn_writer(writer);
    let mut follower: Option<tokio::task::JoinHandle<()>> = None;
    let mut started = false;
    loop {
        let frame = match reader.read_message().await {
            Ok(f) => f,
            Err(_) => break,
        };
        match frame {
            Frame::Ping(p) => {
                let _ = out_tx.send(Out::Pong(p)).await;
            }
            Frame::Pong | Frame::Binary => {}
            Frame::Close(reply) => {
                let _ = out_tx.send(Out::Close(reply)).await;
                break;
            }
            Frame::Text(data) => {
                tracing::debug!(target: "irrd.server.http.event_stream", "event stream {host}: received {data}");
                let sub = tokio::task::block_in_place(|| event_stream::subscribe(&state, &data));
                match sub {
                    Subscribe::Invalid(msg) => {
                        let _ = out_tx.send(Out::Text(msg)).await;
                        let _ = out_tx.send(close_code(CLOSE_UNSUPPORTED)).await;
                        break;
                    }
                    _ if started => {
                        let msg = graphql::value::json_dumps(&graphql::Value::Object(vec![
                            (
                                "message_type".into(),
                                graphql::Value::str("invalid_request"),
                            ),
                            (
                                "errors".into(),
                                graphql::Value::List(vec![graphql::Value::Object(vec![(
                                    "msg".into(),
                                    graphql::Value::str(crate::messages::STREAM_ALREADY_RUNNING),
                                )])]),
                            ),
                        ]));
                        let _ = out_tx.send(Out::Text(msg)).await;
                    }
                    Subscribe::TooHigh(msg) => {
                        let _ = out_tx.send(Out::Text(msg)).await;
                    }
                    Subscribe::Follow(after) => {
                        started = true;
                        if let Some(after) = after {
                            let (tx, mut rx) = mpsc::channel::<String>(256);
                            let fwd = out_tx.clone();
                            let st = state.clone();
                            let h = host.clone();
                            let task = tokio::spawn(async move {
                                let f = tokio::spawn(event_stream::follow(st, after, tx, h));
                                while let Some(m) = rx.recv().await {
                                    if fwd.send(Out::Text(m)).await.is_err() {
                                        break;
                                    }
                                }
                                f.abort();
                            });
                            follower = Some(task);
                        }
                    }
                }
            }
        }
    }
    if let Some(f) = follower {
        f.abort();
    }
    pinger.abort();
    drop(out_tx);
    let _ = writer_task.await;
}

/// What the session's writer task sends.
enum Out {
    Text(String),
    Pong(Vec<u8>),
    /// A close frame with this payload.
    Close(Vec<u8>),
    Ping,
}

fn close_code(code: u16) -> Out {
    Out::Close(code.to_be_bytes().to_vec())
}

/// Everything the server sends goes through one channel, so frames never
/// interleave: the writer task, and the pinger behind uvicorn's
/// `ws_ping_interval`.
fn spawn_writer<W>(
    mut writer: Conn<W>,
) -> (
    mpsc::Sender<Out>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (out_tx, mut out_rx) = mpsc::channel::<Out>(256);
    let writer_task = tokio::spawn(async move {
        while let Some(o) = out_rx.recv().await {
            let r: std::io::Result<()> = match o {
                Out::Text(t) => writer.send_text(&t).await,
                Out::Pong(p) => writer.write_frame(0xA, false, &p).await,
                Out::Ping => writer.write_frame(0x9, false, &rand_payload()).await,
                Out::Close(p) => {
                    let _ = writer.write_frame(0x8, false, &p).await;
                    break;
                }
            };
            if r.is_err() {
                break;
            }
        }
    });
    let pinger = {
        let tx = out_tx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(PING_INTERVAL).await;
                if tx.send(Out::Ping).await.is_err() {
                    break;
                }
            }
        })
    };
    (out_tx, writer_task, pinger)
}

/// ariadne 1.1.1's `GraphQLWSHandler` (the `graphql-ws` protocol of
/// subscriptions-transport-ws) with IRRd's configuration: no `on_connect`
/// hook and no keep-alive messages.
///
/// IRRd has no subscriptions, so a `start` either answers with an `error`
/// message (a syntax error, or the validation error every subscription
/// gets) or is a query or mutation, which ariadne runs through the HTTP
/// handler. There IRRd's `QueryMetadataExtension.format()` reads
/// `request._json`, which a `WebSocket` does not have: the
/// `AttributeError` ends the connection without a close frame. That is
/// what v4 4.5.4 does for every query over a WebSocket, and so what this
/// does, without running the query first.
async fn graphql_session<IO>(io: IO, deflate: Option<Deflate>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (rd, wr) = tokio::io::split(io);
    let mut reader = Conn::new(rd, deflate.clone());
    let (out_tx, writer_task, pinger) = spawn_writer(Conn::new(wr, deflate));
    let crash = graphql_ws_loop(&mut reader, &out_tx).await;
    if let Some(e) = crash {
        tracing::error!(target: "uvicorn.error", "Exception in ASGI application\n{e}");
    }
    pinger.abort();
    drop(out_tx);
    let _ = writer_task.await;
}

/// `handle_websocket()`'s receive loop. `Some` is the exception that
/// escaped it, after which uvicorn drops the connection.
async fn graphql_ws_loop<R: AsyncRead + Unpin>(
    reader: &mut Conn<R>,
    out: &mpsc::Sender<Out>,
) -> Option<String> {
    use graphql::Value;
    let mut acknowledged = false;
    loop {
        let frame = match reader.read_message().await {
            Ok(f) => f,
            Err(_) => return None,
        };
        let text = match frame {
            Frame::Ping(p) => {
                let _ = out.send(Out::Pong(p)).await;
                continue;
            }
            Frame::Pong => continue,
            // receive_json() reads message["text"].
            Frame::Binary => return Some("KeyError: 'text'".into()),
            Frame::Close(reply) => {
                let _ = out.send(Out::Close(reply)).await;
                return None;
            }
            Frame::Text(t) => t,
        };
        let Some(message) = graphql::value::json_loads_str(&text) else {
            return Some("json.decoder.JSONDecodeError".into());
        };
        if !matches!(message, Value::Object(_)) {
            return Some("AttributeError: object has no attribute 'get'".into());
        }
        match message.get("type").and_then(Value::as_str) {
            Some("start") if !acknowledged => {
                // 4401: `start` before `connection_init`.
                let _ = out.send(close_code(4401)).await;
                return None;
            }
            Some("connection_init") => {
                let _ = out
                    .send(Out::Text(r#"{"type":"connection_ack"}"#.to_owned()))
                    .await;
                acknowledged = true;
            }
            Some("connection_terminate") => {
                let _ = out.send(close_code(1000)).await;
                return None;
            }
            Some("start") => {
                let id = message.get("id").cloned().unwrap_or(Value::Null);
                let payload = message.get("payload").cloned().unwrap_or(Value::Null);
                match graphql::ws_start(crate::gql::schema(), &crate::gql::IrrdScalars, &payload) {
                    graphql::WsStart::Error(p) => {
                        let msg = Value::Object(vec![
                            ("type".into(), Value::str("error")),
                            ("id".into(), id),
                            ("payload".into(), p),
                        ]);
                        let _ = out
                            .send(Out::Text(graphql::value::json_dumps_allow_nan(&msg)))
                            .await;
                    }
                    graphql::WsStart::Execute => {
                        return Some(
                            "AttributeError: 'WebSocket' object has no attribute '_json'".into(),
                        );
                    }
                    graphql::WsStart::Crash(e) => return Some(e),
                }
            }
            // `stop` only ends running subscriptions, of which there are
            // none; other types are ignored.
            _ => {}
        }
    }
}

fn rand_payload() -> Vec<u8> {
    let n = store::Timestamp::now().micros() as u32;
    n.to_be_bytes().to_vec()
}

// ---- base64 ----

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(4) {
        return None;
    }
    let val = |c: u8| B64.iter().position(|&x| x == c).map(|p| p as u32);
    let mut out = Vec::new();
    for chunk in s.as_bytes().chunks(4) {
        let mut n = 0u32;
        let mut pad = 0;
        for &c in chunk {
            n <<= 6;
            if c == b'=' {
                pad += 1;
            } else {
                n |= val(c)?;
            }
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_accept_key() {
        let mut h = Sha1::new();
        h.update(b"dGhlIHNhbXBsZSBub25jZQ==");
        h.update(GUID.as_bytes());
        assert_eq!(base64_encode(&h.finalize()), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(
            base64_decode("dGhlIHNhbXBsZSBub25jZQ==").map(|v| v.len()),
            Some(16)
        );
    }

    #[test]
    fn deflate_offers() {
        let d = negotiate("permessage-deflate; client_max_window_bits").expect("offer");
        assert_eq!(d.response, "permessage-deflate");
        assert!(negotiate("x-webkit-deflate-frame").is_none());
    }

    /// Client frames in, server frames out: `text:...`, `close:<hex>`,
    /// `eof` when the server drops the connection, `open` when it waits
    /// for more.
    async fn graphql_ws(sends: &[(u8, &[u8])]) -> Vec<String> {
        let (client, server) = tokio::io::duplex(1 << 16);
        let task = tokio::spawn(graphql_session(server, None));
        let (mut rd, mut wr) = tokio::io::split(client);
        for (op, payload) in sends {
            let mask = [1u8, 2, 3, 4];
            let mut f = vec![0x80 | op];
            if payload.len() < 126 {
                f.push(0x80 | payload.len() as u8);
            } else {
                f.push(0x80 | 126);
                f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            }
            f.extend_from_slice(&mask);
            f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
            wr.write_all(&f).await.expect("write");
        }
        let mut out = Vec::new();
        loop {
            let mut h = [0u8; 2];
            let read =
                tokio::time::timeout(std::time::Duration::from_millis(500), rd.read_exact(&mut h))
                    .await;
            match read {
                Err(_) => {
                    out.push("open".to_owned());
                    break;
                }
                Ok(Err(_)) => {
                    out.push("eof".to_owned());
                    break;
                }
                Ok(Ok(_)) => {}
            }
            let mut len = usize::from(h[1] & 0x7f);
            if len == 126 {
                let mut b = [0u8; 2];
                rd.read_exact(&mut b).await.expect("len");
                len = usize::from(u16::from_be_bytes(b));
            }
            let mut p = vec![0u8; len];
            rd.read_exact(&mut p).await.expect("payload");
            match h[0] & 0x0f {
                0x1 => out.push(format!("text:{}", String::from_utf8_lossy(&p))),
                0x8 => out.push(format!(
                    "close:{}",
                    p.iter().map(|b| format!("{b:02x}")).collect::<String>()
                )),
                op => out.push(format!("op{op}")),
            }
        }
        drop(rd);
        drop(wr);
        let _ = task.await;
        out
    }

    const INIT: (u8, &[u8]) = (1, br#"{"type":"connection_init"}"#);
    const ACK: &str = r#"text:{"type":"connection_ack"}"#;

    /// Frames recorded from v4 4.5.4 (ariadne 1.1.1's GraphQLWSHandler);
    /// parity/corpus/graphql/transport.gq has the same cases.
    #[tokio::test]
    async fn graphql_ws_like_ariadne() {
        assert_eq!(graphql_ws(&[INIT, INIT]).await, [ACK, ACK, "open"]);
        // A query or mutation crashes v4's handler: no close frame.
        let q: (u8, &[u8]) = (
            1,
            br#"{"type":"start","id":"1","payload":{"query":"{ __typename }"}}"#,
        );
        assert_eq!(graphql_ws(&[INIT, q]).await, [ACK, "eof"]);
        let sub: (u8, &[u8]) = (
            1,
            br#"{"type":"start","id":"1","payload":{"query":"subscription { x }"}}"#,
        );
        assert_eq!(
            graphql_ws(&[INIT, sub]).await,
            [
                ACK,
                r#"text:{"type":"error","id":"1","payload":{"message":"The subscription operation is not supported by the schema.","locations":[{"line":1,"column":1}]}}"#,
                "open"
            ]
        );
        let syntax: (u8, &[u8]) = (
            1,
            "{\"type\":\"start\",\"id\":1.5e400,\"payload\":{\"query\":\"{ \u{e9}\"}}".as_bytes(),
        );
        let no_id: (u8, &[u8]) = (1, br#"{"type":"start","payload":{"query":"x"}}"#);
        assert_eq!(
            graphql_ws(&[INIT, syntax, no_id]).await,
            [
                ACK,
                "text:{\"type\":\"error\",\"id\":Infinity,\"payload\":{\"message\":\"Syntax Error: Unexpected character: U+00E9.\",\"locations\":[{\"line\":1,\"column\":3}]}}",
                r#"text:{"type":"error","id":null,"payload":{"message":"Syntax Error: Unexpected Name 'x'.","locations":[{"line":1,"column":1}]}}"#,
                "open"
            ]
        );
        // `start` before `connection_init`: 4401.
        assert_eq!(graphql_ws(&[q]).await, ["close:1131", "eof"]);
        // Unknown types and `stop` are ignored; `connection_terminate`
        // closes normally.
        let other: &[(u8, &[u8])] = &[
            (1, br#"{"type":"foo"}"#),
            (1, br#"{"id":1}"#),
            (1, br#"{"type":"stop","id":"1"}"#),
            (1, br#"{"type":"connection_terminate"}"#),
        ];
        assert_eq!(graphql_ws(other).await, ["close:03e8", "eof"]);
        // What receive_json() and the handler cannot take ends the
        // connection.
        assert_eq!(graphql_ws(&[(1, b"notjson")]).await, ["eof"]);
        assert_eq!(graphql_ws(&[(1, b"[]")]).await, ["eof"]);
        assert_eq!(graphql_ws(&[INIT, (2, b"{}")]).await, [ACK, "eof"]);
        assert_eq!(
            graphql_ws(&[INIT, (1, br#"{"type":"start","id":2}"#)]).await,
            [ACK, "eof"]
        );
        let unknown_op: (u8, &[u8]) = (
            1,
            br#"{"type":"start","payload":{"query":"subscription { a }","operationName":"Nope"}}"#,
        );
        assert_eq!(graphql_ws(&[INIT, unknown_op]).await, [ACK, "eof"]);
        // Close frames are answered as websockets answers them.
        assert_eq!(
            graphql_ws(&[INIT, (8, b"\x0f\xa0bye")]).await,
            [ACK, "close:0fa0627965", "eof"]
        );
        assert_eq!(graphql_ws(&[(8, b"")]).await, ["close:", "eof"]);
        assert_eq!(graphql_ws(&[(8, b"\x03\xed")]).await, ["close:03ea", "eof"]);
        assert_eq!(graphql_ws(&[(8, b"\x01")]).await, ["close:03ea", "eof"]);
        assert_eq!(
            graphql_ws(&[(8, b"\x0f\xa0\xff")]).await,
            ["close:03ef", "eof"]
        );
    }

    #[test]
    fn upgrade_endpoints() {
        assert_eq!(endpoint("/v1/event-stream/"), Endpoint::EventStream);
        assert_eq!(endpoint("/graphql/"), Endpoint::GraphQL);
        assert_eq!(endpoint("/graphql/x"), Endpoint::GraphQL);
        assert_eq!(endpoint("/graphql"), Endpoint::Forbidden);
        assert_eq!(endpoint("/v1/status/"), Endpoint::ServerError);
        assert_eq!(endpoint("/static/x"), Endpoint::ServerError);
        assert_eq!(endpoint("/v1/status"), Endpoint::Forbidden);
        assert_eq!(endpoint("/v1/event-stream/initial/"), Endpoint::Forbidden);
        assert_eq!(percent_decode("/graph%71l/"), "/graphql/");
    }

    #[test]
    fn graphql_handshake_names_the_subprotocol() {
        let mut up = Upgrade {
            accept: "x".into(),
            deflate: negotiate("permessage-deflate"),
            protocol: protocol_for(Endpoint::GraphQL),
        };
        let r = raw_response(&up, &HttpSettings::default());
        assert!(r.contains(
            "Sec-WebSocket-Extensions: permessage-deflate\r\nSec-WebSocket-Protocol: graphql-ws\r\ndate: "
        ));
        up.protocol = protocol_for(Endpoint::EventStream);
        assert!(!raw_response(&up, &HttpSettings::default()).contains("Sec-WebSocket-Protocol"));
    }
}
