//! The whois server: a port of `WhoisTCPServer` and `WhoisWorker`
//! (`irrd/server/whois/server.py`) on tokio.
//!
//! v4 starts `server.whois.max_connections` worker processes and queues
//! accepted connections for them, so a client beyond the limit waits for a
//! free worker rather than being refused. irrd-ng does the same with a
//! semaphore: every connection is accepted and waits for a permit. As in
//! v4, the read timeout (`!t`, default 30 s) only runs while a worker is
//! waiting for the next query line.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use query::{NrtmV3, QuerySettings, WhoisSession, messages};
use store::Store;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

pub(crate) const LOG_TARGET: &str = "irrd.server.whois.server";
const ACCESS_LOG_TARGET: &str = "irrd.server.access_check";

/// What every connection shares.
pub(crate) struct WhoisShared {
    pub(crate) store: Store,
    pub(crate) settings: RwLock<Arc<QuerySettings>>,
    pub(crate) nrtm: Arc<dyn NrtmV3>,
}

/// Accept connections forever.
pub(crate) async fn serve(listener: TcpListener, shared: Arc<WhoisShared>, max_connections: usize) {
    let workers = Arc::new(Semaphore::new(max_connections));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(target: LOG_TARGET, "{}", messages::log_failed_connection(&e.to_string()));
                continue;
            }
        };
        let shared = shared.clone();
        let workers = workers.clone();
        tokio::spawn(async move {
            let Ok(_permit) = workers.acquire_owned().await else {
                return;
            };
            handle_connection(stream, peer, &shared).await;
        });
    }
}

/// `data.decode("utf-8", errors="backslashreplace")`
pub(crate) fn decode_backslashreplace(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        for b in chunk.invalid() {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}

/// `close_request()`: shut down both directions, then close.
fn close(stream: TcpStream) {
    let _ = socket2::SockRef::from(&stream).shutdown(std::net::Shutdown::Both);
    drop(stream);
}

/// Whether the access list admits the client, logging as v4 does.
fn permitted(settings: &QuerySettings, client_ip: &str) -> bool {
    let list = settings.whois_access_list.as_deref();
    match settings.is_client_permitted(client_ip, list, false) {
        Some(true) => true,
        Some(false) => {
            tracing::info!(
                target: ACCESS_LOG_TARGET,
                "{}",
                messages::log_not_in_access_list(list.unwrap_or_default(), client_ip)
            );
            false
        }
        None => {
            tracing::error!(
                target: ACCESS_LOG_TARGET,
                "{}",
                messages::log_unreadable_client(client_ip, "invalid address")
            );
            false
        }
    }
}

async fn handle_connection(stream: TcpStream, peer: std::net::SocketAddr, shared: &WhoisShared) {
    let client_ip = peer.ip().to_string();
    let client_str = format!("{client_ip}:{}", peer.port());
    let settings = shared
        .settings
        .read()
        .map(|s| s.clone())
        .unwrap_or_default();

    let mut stream = stream;
    if !permitted(&settings, &client_ip) {
        let _ = stream.write_all(messages::WHOIS_ACCESS_DENIED).await;
        close(stream);
        return;
    }

    let mut session = WhoisSession::new(settings, shared.nrtm.clone(), &client_ip, &client_str);
    let (read_half, mut write_half) = stream.split();
    let mut reader = BufReader::new(read_half);
    let mut line: Vec<u8> = Vec::with_capacity(256);
    let mut out: Vec<u8> = Vec::with_capacity(4096);
    loop {
        line.clear();
        let timeout = Duration::from_secs(session.timeout);
        match tokio::time::timeout(timeout, reader.read_until(b'\n', &mut line)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(_)) => {}
        }
        let decoded = decode_backslashreplace(&line);
        let query = rpsl::python::strip(&decoded);
        if query.is_empty() {
            continue;
        }
        tracing::debug!(target: LOG_TARGET, "{}", messages::log_processing(&client_str, query));

        let start = Instant::now();
        if rpsl::python::upper(query) == "!Q" {
            tracing::debug!(target: LOG_TARGET, "{}", messages::log_closed_per_request(&client_str));
            break;
        }
        out.clear();
        tokio::task::block_in_place(|| session.query_whois(&shared.store, query, &mut out));
        if write_half.write_all(&out).await.is_err() {
            break;
        }
        tracing::info!(
            target: LOG_TARGET,
            "{}",
            messages::log_sent_answer(&client_str, start.elapsed().as_secs_f64(), out.len(), query)
        );
        if !session.multiple_command_mode {
            tracing::debug!(target: LOG_TARGET, "{}", messages::log_auto_closed(&client_str));
            break;
        }
    }
    close(stream);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_like_python_backslashreplace() {
        assert_eq!(decode_backslashreplace(b"!v\r\n"), "!v\r\n");
        assert_eq!(decode_backslashreplace(b"a\xffb"), "a\\xffb");
        assert_eq!(decode_backslashreplace(b"\xe2\x82A"), "\\xe2\\x82A");
        assert_eq!(decode_backslashreplace("é".as_bytes()), "é");
    }
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    async fn ask(addr: std::net::SocketAddr, q: &str) -> String {
        let mut s = TcpStream::connect(addr).await.expect("connect");
        s.write_all(format!("{q}\n").as_bytes())
            .await
            .expect("write");
        let mut out = String::new();
        s.read_to_string(&mut out).await.expect("read");
        out
    }

    /// A panic while answering one query is contained to that query: the
    /// client gets v4's internal error, the same connection can go on in
    /// multiple-command mode, and other connections keep being served.
    #[test]
    fn panic_is_contained_to_one_query() {
        let dir = std::env::temp_dir().join(format!("irrd-ng-whois-panic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut o = store::StoreOptions::new(&dir);
        o.initial_map_size = 16 << 20;
        let st = Store::open(&o, store::StoreSettings::default()).expect("store");
        let settings = Arc::new(QuerySettings {
            version: "4.5.4".into(),
            ..QuerySettings::default()
        });
        let shared = Arc::new(WhoisShared {
            store: st.clone(),
            settings: RwLock::new(settings.clone()),
            nrtm: Arc::new(query::NrtmServer),
        });
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            tokio::spawn(serve(listener, shared, 2));
            assert_eq!(
                ask(addr, "!~panic").await,
                "F An internal error occurred while processing this query.\n"
            );
            assert_eq!(
                ask(addr, "-k\n!~panic\n!v\n!q").await,
                "%  No entries found for the selected source(s).\n\n\nF An internal error occurred while processing this query.\nA22\nIRRd -- version 4.5.4\nC\n"
            );
            for _ in 0..4 {
                assert_eq!(ask(addr, "!v").await, "A22\nIRRd -- version 4.5.4\nC\n");
            }
        });
        // The read transaction of the panicking query was released.
        st.write(|tx| tx.record_serial_seen("TEST", 1))
            .expect("write");
        assert!(st.read().is_ok());
        let mut s = WhoisSession::new(settings, Arc::new(query::NrtmServer), "192.0.2.1", "x");
        let r = s.query_http(&st, "!~panic");
        assert_eq!(r.response_type, query::ResponseType::ErrorInternal);
        assert_eq!(s.result(), query::messages::INTERNAL_ERROR);
        drop(st);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
