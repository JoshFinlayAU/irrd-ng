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
            let (k, v) = p.split_once('=').map_or((p, None), |(k, v)| (k.trim(), Some(v.trim().trim_matches('"'))));
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
) -> Reply {
    let key = header(headers, "sec-websocket-key");
    let version = header(headers, "sec-websocket-version");
    let key_ok = base64_decode(key.trim()).is_some_and(|k| k.len() == 16);
    if !key_ok || version.trim() != "13" {
        let mut r = Reply::text(
            StatusCode::BAD_REQUEST,
            "Failed to open a WebSocket connection: invalid Sec-WebSocket-Key header.\n",
        );
        r.secured = false;
        return r;
    }
    let mut h = Sha1::new();
    h.update(key.trim().as_bytes());
    h.update(GUID.as_bytes());
    let accept = base64_encode(&h.finalize());
    let deflate = negotiate(&header(headers, "sec-websocket-extensions"));
    let up = Upgrade {
        accept,
        deflate: deflate.clone(),
    };
    if let Some(on) = on_upgrade {
        let host = host.to_owned();
        let settings = settings.clone();
        tokio::spawn(async move {
            if let Ok(io) = on.await {
                let io = hyper_util::rt::TokioIo::new(io);
                session(state, io, deflate, host, settings).await;
            }
        });
    }
    let mut r = Reply::empty(StatusCode::SWITCHING_PROTOCOLS);
    r.upgrade = Some(up);
    r
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
    put("date", &httpdate::fmt_http_date(std::time::SystemTime::now()));
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
    Close(Option<u16>),
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
                0x8 => {
                    let code = (payload.len() >= 2).then(|| u16::from_be_bytes([payload[0], payload[1]]));
                    return Ok(Frame::Close(code));
                }
                0x9 => return Ok(Frame::Ping(payload)),
                0xA => return Ok(Frame::Pong),
                0x0 | 0x1 | 0x2 => {
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
    let header = match tokio::task::block_in_place(|| event_stream::stream_status(&state, &settings)) {
        Ok(h) => h,
        Err(_) => return,
    };
    if writer.send_text(&header).await.is_err() {
        return;
    }
    // Everything the server sends goes through one channel, so frames
    // never interleave.
    enum Out {
        Text(String),
        Pong(Vec<u8>),
        Close(u16),
        Ping,
    }
    let (out_tx, mut out_rx) = mpsc::channel::<Out>(256);
    let writer_task = tokio::spawn(async move {
        while let Some(o) = out_rx.recv().await {
            let r: std::io::Result<()> = match o {
                Out::Text(t) => writer.send_text(&t).await,
                Out::Pong(p) => writer.write_frame(0xA, false, &p).await,
                Out::Ping => writer.write_frame(0x9, false, &rand_payload()).await,
                Out::Close(c) => {
                    let _ = writer.close(c).await;
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
            Frame::Close(code) => {
                let _ = out_tx.send(Out::Close(code.unwrap_or(1000))).await;
                break;
            }
            Frame::Text(data) => {
                tracing::debug!(target: "irrd.server.http.event_stream", "event stream {host}: received {data}");
                let sub = tokio::task::block_in_place(|| event_stream::subscribe(&state, &data));
                match sub {
                    Subscribe::Invalid(msg) => {
                        let _ = out_tx.send(Out::Text(msg)).await;
                        let _ = out_tx.send(Out::Close(CLOSE_UNSUPPORTED)).await;
                        break;
                    }
                    _ if started => {
                        let msg = graphql::value::json_dumps(&graphql::Value::Object(vec![
                            ("message_type".into(), graphql::Value::str("invalid_request")),
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

fn rand_payload() -> Vec<u8> {
    let n = store::Timestamp::now().micros() as u32;
    n.to_be_bytes().to_vec()
}

// ---- base64 ----

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 4 != 0 {
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
        assert_eq!(base64_decode("dGhlIHNhbXBsZSBub25jZQ==").map(|v| v.len()), Some(16));
    }

    #[test]
    fn deflate_offers() {
        let d = negotiate("permessage-deflate; client_max_window_bits").expect("offer");
        assert_eq!(d.response, "permessage-deflate");
        assert!(negotiate("x-webkit-deflate-frame").is_none());
    }
}
