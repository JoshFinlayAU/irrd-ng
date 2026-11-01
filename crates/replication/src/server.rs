//! The active's side: serve the replication log to standbys.

use std::sync::Arc;
use std::time::{Duration, Instant};

use store::Store;
use store::replog::{Entry, write_spool_row};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

use crate::protocol::{self, Conn, Kind, Reader, Writer};
use crate::{Error, LOG_TARGET, ServerSettings, messages};

/// How much log one `ENTRIES` frame carries at most (roughly).
const BATCH_BYTES: usize = 4 << 20;
/// How often an idle stream looks for new entries.
const POLL: Duration = Duration::from_millis(200);
/// How long the handshake may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Snapshot rows per frame (roughly, in bytes).
const SNAPSHOT_FRAME: usize = 1 << 20;

/// Open the listening socket.
pub fn bind(settings: &ServerSettings) -> std::io::Result<TcpListener> {
    let ip: std::net::IpAddr = settings
        .interface
        .parse()
        .map_err(|_| std::io::Error::other(format!("invalid interface {}", settings.interface)))?;
    let addr = std::net::SocketAddr::new(ip, settings.port);
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(16)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

async fn blocking<R: Send + 'static>(
    f: impl FnOnce() -> Result<R, store::StoreError> + Send + 'static,
) -> Result<R, Error> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::Protocol(e.to_string()))?
        .map_err(Error::Store)
}

/// Accept standbys until `shutdown` turns true, and trim the log past
/// retention once a minute.
pub async fn serve(
    listener: TcpListener,
    store: Store,
    settings: Arc<ServerSettings>,
    mut shutdown: watch::Receiver<bool>,
) {
    let trim_store = store.clone();
    let retention = settings.retention;
    let mut trim_shutdown = shutdown.clone();
    tokio::spawn(async move {
        loop {
            let cutoff = store::Timestamp(
                store::Timestamp::now()
                    .0
                    .saturating_sub(retention.as_micros() as i64),
            );
            let s = trim_store.clone();
            match blocking(move || s.trim_replication_log(cutoff)).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(target: LOG_TARGET, "{}", messages::trimmed(n)),
                Err(e) => tracing::error!(target: LOG_TARGET, "{e}"),
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                _ = trim_shutdown.changed() => return,
            }
        }
    });
    loop {
        let accepted = tokio::select! {
            a = listener.accept() => a,
            _ = shutdown.changed() => return,
        };
        let Ok((stream, peer)) = accepted else {
            continue;
        };
        let _ = stream.set_nodelay(true);
        let (store, settings, shutdown) = (store.clone(), settings.clone(), shutdown.clone());
        tokio::spawn(async move {
            let peer = peer.to_string();
            match handle(stream, &peer, store, settings, shutdown).await {
                Ok(()) => {}
                Err(Error::Remote(e)) | Err(Error::Protocol(e)) => {
                    tracing::warn!(target: LOG_TARGET, "{}", messages::standby_refused(&peer, &e));
                }
                Err(e) => {
                    tracing::info!(target: LOG_TARGET, "{}", messages::standby_disconnected(&peer, &e.to_string()));
                }
            }
        });
    }
}

async fn handshake(
    conn: &mut Conn<TcpStream>,
    settings: &ServerSettings,
) -> Result<(String, u64), Error> {
    let (kind, p) = tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.recv())
        .await
        .map_err(|_| Error::Timeout)??;
    if kind != Kind::Hello {
        return Err(Error::Protocol("expected HELLO".into()));
    }
    let mut r = Reader(&p);
    r.magic()?;
    let (proto, schema, cn) = (r.u32()?, r.u32()?, r.array32()?);
    let refuse = if proto != protocol::PROTOCOL_VERSION {
        Some(messages::protocol_mismatch(
            protocol::PROTOCOL_VERSION,
            proto,
        ))
    } else if schema != store::SCHEMA_VERSION {
        Some(messages::schema_mismatch(store::SCHEMA_VERSION, schema))
    } else {
        None
    };
    if let Some(msg) = refuse {
        conn.send(Kind::Error, msg.as_bytes()).await?;
        return Err(Error::Protocol(msg));
    }
    let sn = protocol::nonce()?;
    let challenge = Writer::default()
        .u32(protocol::PROTOCOL_VERSION)
        .u32(store::SCHEMA_VERSION)
        .bytes(&sn)
        .bytes(&protocol::server_proof(&settings.secret, &cn, &sn))
        .0;
    conn.send(Kind::Challenge, &challenge).await?;
    let (kind, p) = tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.recv())
        .await
        .map_err(|_| Error::Timeout)??;
    if kind != Kind::Auth {
        return Err(Error::Protocol("expected AUTH".into()));
    }
    let mut r = Reader(&p);
    let proof = r.array32()?;
    if !protocol::constant_time_eq(&proof, &protocol::client_proof(&settings.secret, &cn, &sn)) {
        conn.send(Kind::Error, messages::AUTH_FAILED.as_bytes())
            .await?;
        return Err(Error::Protocol(messages::AUTH_FAILED.into()));
    }
    conn.set_key(protocol::session_key(&settings.secret, &cn, &sn));
    Ok((r.str()?, r.u64()?))
}

async fn handle(
    stream: TcpStream,
    peer: &str,
    store: Store,
    settings: Arc<ServerSettings>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Error> {
    let mut conn = Conn::new(stream);
    let (follow_id, follow_seq) = handshake(&mut conn, &settings).await?;

    let s = store.clone();
    let st = blocking(move || s.replication_state()).await?;
    let Some(id) = st.id.clone() else {
        conn.send(Kind::Error, messages::LOG_NOT_ENABLED.as_bytes())
            .await?;
        return Err(Error::Protocol(messages::LOG_NOT_ENABLED.into()));
    };
    let continues = follow_id == id
        && follow_seq <= st.last_seq
        && (follow_seq == st.last_seq || st.first_seq.is_some_and(|f| follow_seq + 1 >= f));
    let mut cursor = if continues {
        tracing::info!(target: LOG_TARGET, "{}", messages::standby_connected(peer, &format!("from log entry {}", follow_seq + 1)));
        follow_seq
    } else {
        tracing::info!(target: LOG_TARGET, "{}", messages::standby_connected(peer, "a snapshot"));
        send_snapshot(&mut conn, &store, peer, &id).await?
    };

    let mut last_sent = Instant::now();
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let s = store.clone();
        let (current, entries) =
            blocking(move || s.replication_entries(cursor, BATCH_BYTES)).await?;
        if current.as_deref() != Some(id.as_str()) {
            let msg = "the active's replication log was reset";
            conn.send(Kind::Error, msg.as_bytes()).await?;
            return Err(Error::Protocol(msg.into()));
        }
        if entries.is_empty() {
            if last_sent.elapsed() >= settings.heartbeat {
                let hb = Writer::default().str(&id).u64(cursor).0;
                conn.send(Kind::Heartbeat, &hb).await?;
                last_sent = Instant::now();
            }
            tokio::select! {
                _ = tokio::time::sleep(POLL) => {}
                _ = shutdown.changed() => return Ok(()),
                _ = conn.closed() => {
                    return Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
                }
            }
            continue;
        }
        if entries[0].0 != cursor + 1 {
            // Trimmed while this standby was catching up.
            cursor = send_snapshot(&mut conn, &store, peer, &id).await?;
            last_sent = Instant::now();
            continue;
        }
        let cut = entries
            .iter()
            .position(|(_, b)| Entry::is_resync(b).unwrap_or(true))
            .unwrap_or(entries.len());
        if cut > 0 {
            let mut w = Writer::default().str(&id).u32(cut as u32);
            for (seq, bytes) in &entries[..cut] {
                w = w.u64(*seq).blob(bytes);
            }
            conn.send(Kind::Entries, &w.0).await?;
            cursor = entries[cut - 1].0;
        }
        if cut < entries.len() {
            cursor = send_snapshot(&mut conn, &store, peer, &id).await?;
        }
        last_sent = Instant::now();
    }
}

enum Snap {
    State(Option<String>, u64),
    Rows(Vec<u8>),
    End(u64),
    Failed(String),
}

/// Stream every replicated row from one read transaction. Returns the log
/// sequence the snapshot is at.
async fn send_snapshot(
    conn: &mut Conn<TcpStream>,
    store: &Store,
    peer: &str,
    id: &str,
) -> Result<u64, Error> {
    let (tx, mut rx) = mpsc::channel::<Snap>(4);
    let s = store.clone();
    tokio::task::spawn_blocking(move || {
        let mut buf = Vec::with_capacity(SNAPSHOT_FRAME + 4096);
        let mut rows = 0u64;
        let gone = || store::StoreError::Aborted("standby went away".into());
        let r = s.replication_snapshot(
            &mut |st| {
                tx.blocking_send(Snap::State(st.id.clone(), st.last_seq))
                    .map_err(|_| gone())
            },
            &mut |table, k, v| {
                let _ = write_spool_row(&mut buf, table, k, v);
                rows += 1;
                if buf.len() >= SNAPSHOT_FRAME {
                    let full =
                        std::mem::replace(&mut buf, Vec::with_capacity(SNAPSHOT_FRAME + 4096));
                    tx.blocking_send(Snap::Rows(full)).map_err(|_| gone())?;
                }
                Ok(())
            },
        );
        let _ = match r {
            Ok(_) => {
                if !buf.is_empty() {
                    let _ = tx.blocking_send(Snap::Rows(buf));
                }
                tx.blocking_send(Snap::End(rows))
            }
            Err(e) => tx.blocking_send(Snap::Failed(e.to_string())),
        };
    });
    let mut seq = 0;
    while let Some(msg) = rx.recv().await {
        match msg {
            Snap::State(sid, s) => {
                if sid.as_deref() != Some(id) {
                    return Err(Error::Protocol(
                        "the active's replication log was reset".into(),
                    ));
                }
                seq = s;
                tracing::info!(target: LOG_TARGET, "{}", messages::sending_snapshot(peer, seq));
                let p = Writer::default().str(id).u64(seq).0;
                conn.send(Kind::SnapshotBegin, &p).await?;
            }
            Snap::Rows(b) => conn.send(Kind::SnapshotRows, &b).await?,
            Snap::End(rows) => {
                conn.send(Kind::SnapshotEnd, &Writer::default().u64(rows).0)
                    .await?;
                return Ok(seq);
            }
            Snap::Failed(e) => return Err(Error::Protocol(e)),
        }
    }
    Err(Error::Protocol("snapshot ended early".into()))
}
