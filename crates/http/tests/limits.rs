//! Request limits over a real socket: an oversized body is refused, and
//! bodies nested too deeply end in v4's `RecursionError` (a 500) instead of
//! overflowing the stack and taking every client down with the process.

#![allow(clippy::unwrap_used, clippy::expect_used, unreachable_pub)]

use std::sync::{Arc, RwLock};

use http::{HttpSettings, HttpState, MAX_BODY};
use query::QuerySettings;
use store::{Store, StoreOptions, StoreSettings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Tmp(std::path::PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn start() -> (Tmp, std::net::SocketAddr) {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("irrd-ng-http-limits-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    let mut o = StoreOptions::new(&p);
    o.initial_map_size = 16 << 20;
    let store = Store::open(&o, StoreSettings::default()).expect("store");
    let state = Arc::new(HttpState {
        store,
        query: RwLock::new(Arc::new(QuerySettings {
            version: "4.5.4".into(),
            ..QuerySettings::default()
        })),
        http: RwLock::new(Arc::new(HttpSettings::default())),
        nrtm: Arc::new(query::NrtmServer),
        submit: RwLock::new(Arc::new(auth::SubmitSettings::default())),
        startup_time: 0,
        events: http::Events::new(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(http::serve(listener, state));
    (Tmp(p), addr)
}

/// POST `body` and return the status line.
async fn post(addr: std::net::SocketAddr, path: &str, body: &[u8]) -> String {
    let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await.expect("write");
    // The server may answer and close before taking the whole body.
    let _ = s.write_all(body).await;
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    let text = String::from_utf8_lossy(&out);
    text.lines().next().unwrap_or_default().to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_limits() {
    let (_tmp, addr) = start().await;
    // Ordinary bodies are untouched.
    assert_eq!(
        post(addr, "/graphql/", b"[").await,
        "HTTP/1.1 400 Bad Request"
    );
    // Deep nesting, far past anything Python would decode.
    let deep = "[".repeat(1_000_000);
    assert_eq!(
        post(addr, "/graphql/", deep.as_bytes()).await,
        "HTTP/1.1 500 Internal Server Error"
    );
    assert_eq!(
        post(addr, "/v1/submit/", deep.as_bytes()).await,
        "HTTP/1.1 500 Internal Server Error"
    );
    let query = format!(r#"{{"query": "{}"}}"#, "{ a ".repeat(100_000));
    assert_eq!(
        post(addr, "/graphql/", query.as_bytes()).await,
        "HTTP/1.1 500 Internal Server Error"
    );
    // Over the size limit.
    let big = vec![b' '; MAX_BODY + 1];
    assert_eq!(
        post(addr, "/graphql/", &big).await,
        "HTTP/1.1 413 Payload Too Large"
    );
    assert_eq!(
        post(addr, "/v1/submit/", &big).await,
        "HTTP/1.1 413 Payload Too Large"
    );
    // And the server is still there.
    assert_eq!(
        post(addr, "/graphql/", b"[").await,
        "HTTP/1.1 400 Bad Request"
    );
}

/// A long chain of fragments, unauthenticated and well under the body
/// limit, is v4's `RecursionError` (a 500) and leaves the server running,
/// on worker threads with the daemon's 8 MiB stacks.
#[test]
fn fragment_chain_is_a_recursion_error() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(8 << 20)
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let (_tmp, addr) = start().await;
        let n = 20_000;
        let mut query = String::from("query{...F0} ");
        for i in 0..n {
            query.push_str(&format!("fragment F{i} on Query{{...F{}}} ", i + 1));
        }
        query.push_str(&format!("fragment F{n} on Query{{__typename}}"));
        let body = format!(r#"{{"query": "{query}"}}"#);
        assert!(body.len() > 650_000 && body.len() < MAX_BODY);
        assert_eq!(
            post(addr, "/graphql/", body.as_bytes()).await,
            "HTTP/1.1 500 Internal Server Error"
        );
        // And the server is still there.
        assert_eq!(
            post(addr, "/graphql/", br#"{"query": "{__typename}"}"#).await,
            "HTTP/1.1 200 OK"
        );
    });
}
