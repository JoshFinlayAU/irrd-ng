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
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

pub(crate) const LOG_TARGET: &str = "irrd.server.whois.server";
const ACCESS_LOG_TARGET: &str = "irrd.server.access_check";

/// The longest query line read. v4's `readline()` has no limit, so a
/// client could make a worker buffer as much as it can send before the
/// read timeout; in irrd-ng that memory would come out of the one process
/// every client shares. Real queries are far shorter.
pub(crate) const MAX_LINE: usize = 1 << 20;

/// How long a response may make no progress because the client is not
/// reading it. v4 has no limit, so a client that stops reading holds a
/// worker for good.
pub(crate) const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(120);

/// After a failed `accept()` (out of file descriptors, say), wait this
/// long before the next one instead of spinning.
pub(crate) const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

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
                tokio::time::sleep(ACCEPT_BACKOFF).await;
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

/// Write all of `buf`, giving up if the client accepts nothing for
/// [`WRITE_STALL_TIMEOUT`]. Whether it all went out.
async fn write_or_stall<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, buf: &[u8]) -> bool {
    let mut rest = buf;
    while !rest.is_empty() {
        match tokio::time::timeout(WRITE_STALL_TIMEOUT, w.write(rest)).await {
            Ok(Ok(n)) if n > 0 => rest = &rest[n..],
            _ => return false,
        }
    }
    true
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
        let mut limited = (&mut reader).take(MAX_LINE as u64);
        match tokio::time::timeout(timeout, limited.read_until(b'\n', &mut line)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(_)) => {}
        }
        if line.len() >= MAX_LINE && !line.ends_with(b"\n") {
            tracing::info!(target: LOG_TARGET, "{}", crate::messages::whois_line_too_long(&client_str));
            break;
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
        // Each query sees the settings as they are now, as v4's
        // get_setting() does in a worker that received SIGHUP.
        if let Ok(current) = shared.settings.read() {
            session.update_settings(current.clone());
        }
        out.clear();
        tokio::task::block_in_place(|| session.query_whois(&shared.store, query, &mut out));
        if !write_or_stall(&mut write_half, &out).await {
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
            // A query line past MAX_LINE closes the connection unanswered;
            // a long one within it is read as usual.
            let pad = " ".repeat(MAX_LINE - 10);
            assert_eq!(
                ask(addr, &format!("{pad}!v")).await,
                "A22\nIRRd -- version 4.5.4\nC\n"
            );
            let mut s = TcpStream::connect(addr).await.expect("connect");
            let _ = s.write_all(format!("{pad}{pad}!v\n").as_bytes()).await;
            let mut out = Vec::new();
            let _ = s.read_to_end(&mut out).await;
            assert_eq!(out, b"");
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

    /// Read what the server sends until it pauses.
    async fn read_reply(s: &mut TcpStream) -> String {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(300), s.read(&mut buf)).await
        {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        String::from_utf8(out).expect("utf8")
    }

    /// A SIGHUP replaces the shared settings; a connection that is already
    /// open answers its next query with them, as v4's whois workers do.
    #[test]
    fn open_connection_sees_reloaded_settings() {
        let dir = std::env::temp_dir().join(format!("irrd-ng-whois-reload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut o = store::StoreOptions::new(&dir);
        o.initial_map_size = 16 << 20;
        let st = Store::open(&o, store::StoreSettings::default()).expect("store");
        st.write(|tx| {
            let status = store::DatabaseStatus::new("TEST", tx.transaction_time());
            tx.put_database_status(&status)
        })
        .expect("write");
        let settings = |permitted: bool| {
            let mut s = QuerySettings {
                version: "4.5.4".into(),
                sources: vec!["TEST".into()],
                ..QuerySettings::default()
            };
            s.per_source.insert(
                "TEST".into(),
                query::SourceQuerySettings {
                    nrtm_access_list_unfiltered: Some("unfiltered".into()),
                    ..query::SourceQuerySettings::default()
                },
            );
            if permitted {
                s.access_lists.insert(
                    "unfiltered".into(),
                    vec![rpsl::Ip::parse("127.0.0.1", 0).expect("ip")],
                );
            }
            Arc::new(s)
        };
        let shared = Arc::new(WhoisShared {
            store: st.clone(),
            settings: RwLock::new(settings(true)),
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
            tokio::spawn(serve(listener, shared.clone(), 2));
            let mut s = TcpStream::connect(addr).await.expect("connect");
            s.write_all(b"-k\n").await.expect("write");
            let _ = read_reply(&mut s).await;
            s.write_all(b"-q sources\n").await.expect("write");
            assert_eq!(read_reply(&mut s).await, "TEST:3:X:Unknown\n\n\n");
            // What the SIGHUP handler in daemon.rs does.
            *shared.settings.write().expect("lock") = settings(false);
            s.write_all(b"-q sources\n").await.expect("write");
            assert_eq!(read_reply(&mut s).await, "TEST:3:N:Unknown\n\n\n");
            s.write_all(b"-g TEST:3:1-LAST\n").await.expect("write");
            assert_eq!(read_reply(&mut s).await, "%% ERROR: Access denied\n\n\n");
        });
        drop(st);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
