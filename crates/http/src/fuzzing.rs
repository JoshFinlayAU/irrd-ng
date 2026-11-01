//! Entry points for the fuzz targets in `fuzz/`. Not a stable API.

use std::io::Cursor;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// Run a future that never waits: every stream here is in memory.
fn now<F: Future>(f: F) -> Option<F::Output> {
    let mut cx = Context::from_waker(Waker::noop());
    match pin!(f).poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// A `multipart/form-data` GraphQL request. The first line of `data` is
/// the content type's parameters, the rest the body.
pub fn multipart(data: &[u8]) {
    let (params, body) = match data.iter().position(|b| *b == b'\n') {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };
    let content_type = format!("multipart/form-data; {}", String::from_utf8_lossy(params));
    let _ = crate::multipart::extract(&content_type, body);
}

/// Client WebSocket frames, read as both endpoints read them. The first
/// byte picks whether `permessage-deflate` was negotiated.
pub fn websocket(data: &[u8]) {
    let Some((&mode, frames)) = data.split_first() else {
        return;
    };
    let deflate = match mode % 3 {
        0 => None,
        1 => crate::websocket::negotiate_for_fuzzing("permessage-deflate"),
        _ => crate::websocket::negotiate_for_fuzzing(
            "permessage-deflate; client_no_context_takeover; client_max_window_bits=9",
        ),
    };
    let mut conn = crate::websocket::Conn::new(Cursor::new(frames.to_vec()), deflate);
    for _ in 0..64 {
        match now(conn.read_message()) {
            Some(Ok(crate::websocket::Frame::Text(t))) => {
                let _ = graphql::value::json_loads_str(&t);
            }
            Some(Ok(_)) => {}
            _ => break,
        }
    }
}

/// A `/graphql/` JSON body: decoded, then the query parsed and validated
/// against IRRd's schema, without running it.
pub fn graphql(body: &[u8]) {
    let Some(data) = graphql::value::json_loads(body) else {
        return;
    };
    let _ = graphql::ws_start(crate::gql::schema(), &crate::gql::IrrdScalars, &data);
    if let Some(query) = data.get("query").and_then(graphql::Value::as_str) {
        let _ = graphql::validate_only(crate::gql::schema(), &crate::gql::IrrdScalars, query);
    }
}

/// A GraphQL document on its own, parsed and validated.
pub fn graphql_document(query: &str) {
    let _ = graphql::validate_only(crate::gql::schema(), &crate::gql::IrrdScalars, query);
}
