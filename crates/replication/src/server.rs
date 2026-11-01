//! The active's side: serve the replication log to standbys.

use std::sync::Arc;
use std::time::{Duration, Instant};

use store::Store;
use store::replog::{Entry, write_spool_row};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

use crate::gate::{self, Gate, Refusal};
use crate::protocol::{self, Conn, Kind, Stream, Transcript, Writer};
use crate::{Error, LOG_TARGET, ServerSettings, messages, tls};

/// How much log one `ENTRIES` frame carries at most (roughly).
const BATCH_BYTES: usize = 4 << 20;
/// How often an idle stream looks for new entries.
const POLL: Duration = Duration::from_millis(200);
/// At most one warning a minute about refused connections.
const REFUSAL_WARNING_INTERVAL: Duration = Duration::from_secs(60);
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
    let gate = Gate::new(
        settings.max_unauthenticated,
        settings.max_unauthenticated_per_ip,
    );
    let mut last_refusal_warning: Option<Instant> = None;
    loop {
        let accepted = tokio::select! {
            a = listener.accept() => a,
            _ = shutdown.changed() => return,
        };
        let Ok((stream, peer)) = accepted else {
            continue;
        };
        let pending = match gate.admit(peer.ip(), Instant::now()) {
            Ok(p) => p,
            Err(refusal) => {
                // Closed at once, without a word: the peer has proved
                // nothing. Warn now and then, so a flood does not flood
                // the log too.
                let why = match refusal {
                    Refusal::Busy => messages::TOO_MANY_PENDING,
                    Refusal::BusyPeer => messages::TOO_MANY_PENDING_PEER,
                    Refusal::LockedOut => messages::LOCKED_OUT,
                };
                if last_refusal_warning.is_none_or(|t| t.elapsed() >= REFUSAL_WARNING_INTERVAL) {
                    last_refusal_warning = Some(Instant::now());
                    tracing::warn!(target: LOG_TARGET, "{}", messages::standby_refused(&peer.to_string(), why));
                } else {
                    tracing::debug!(target: LOG_TARGET, "{}", messages::standby_refused(&peer.to_string(), why));
                }
                drop(stream);
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let (store, settings, shutdown, gate) = (
            store.clone(),
            settings.clone(),
            shutdown.clone(),
            gate.clone(),
        );
        tokio::spawn(async move {
            let ip = peer.ip();
            let peer = peer.to_string();
            match handle(stream, &peer, ip, pending, &gate, store, settings, shutdown).await {
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

/// Set up the connection's byte stream: TLS when the active has a
/// certificate, plain TCP when it does not. Each end insists on its own
/// choice, so a standby that disagrees is refused rather than served in
/// the clear.
async fn open_stream(stream: TcpStream, settings: &ServerSettings) -> Result<Stream, Error> {
    let mut first = [0u8; 1];
    let n = stream.peek(&mut first).await?;
    let wants_tls = n == 1 && first[0] == tls::TLS_HANDSHAKE_BYTE;
    match (&settings.tls, wants_tls) {
        (Some(config), true) => {
            let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
            let s = acceptor
                .accept(stream)
                .await
                .map_err(|e| Error::Protocol(messages::tls_failed(&e.to_string())))?;
            Ok(Box::new(s))
        }
        (Some(_), false) => {
            // Read the standby's HELLO before answering, so the ERROR is
            // not lost to a reset from closing with unread data.
            let mut conn = Conn::new(Box::new(stream) as Stream);
            if conn.recv().await.is_ok() {
                conn.send(Kind::Error, messages::REQUIRES_TLS.as_bytes())
                    .await?;
            }
            Err(Error::Protocol(messages::REQUIRES_TLS.into()))
        }
        (None, true) => Err(Error::Protocol(messages::TLS_NOT_CONFIGURED.into())),
        (None, false) => Ok(Box::new(stream)),
    }
}

/// The active's side of the handshake (see [`protocol`]): the standby
/// proves the secret first, and only then does the active prove it too.
/// Returns the log id and sequence the standby has applied.
async fn handshake(
    conn: &mut Conn<Stream>,
    settings: &ServerSettings,
    ip: std::net::IpAddr,
    gate: &Gate,
) -> Result<(String, u64), Error> {
    let mut transcript = Transcript::new();
    let (kind, p) = conn.recv().await?;
    if kind != Kind::Hello {
        return Err(Error::Protocol("expected HELLO".into()));
    }
    let (proto, schema, _) = protocol::parse_hello(&p)?;
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
    transcript.add(Kind::Hello, &p);
    let sn = protocol::nonce()?;
    let challenge = Writer::default()
        .u32(protocol::PROTOCOL_VERSION)
        .u32(store::SCHEMA_VERSION)
        .bytes(&sn)
        .0;
    conn.send(Kind::Challenge, &challenge).await?;
    transcript.add(Kind::Challenge, &challenge);
    let (kind, p) = conn.recv().await?;
    if kind != Kind::Auth {
        return Err(Error::Protocol("expected AUTH".into()));
    }
    let (body, proof) = protocol::split_auth(&p)?;
    transcript.add(Kind::Auth, body);
    if !protocol::constant_time_eq(&proof, &transcript.standby_proof(&settings.key)) {
        if gate.failed(ip, Instant::now()) {
            tracing::warn!(target: LOG_TARGET, "{}", messages::locked_out(&ip.to_string()));
        }
        conn.send(Kind::Error, messages::AUTH_FAILED.as_bytes())
            .await?;
        return Err(Error::Protocol(messages::AUTH_FAILED.into()));
    }
    gate.succeeded(ip);
    let position = protocol::parse_auth_position(body)?;
    // The active's proof covers the standby's.
    transcript.add_proof(&proof);
    let accept = transcript.active_proof(&settings.key);
    conn.send(Kind::Accept, &accept).await?;
    transcript.add(Kind::Accept, &accept);
    conn.set_key(transcript.session_key(&settings.key));
    Ok(position)
}

#[allow(clippy::too_many_arguments)]
async fn handle(
    stream: TcpStream,
    peer: &str,
    ip: std::net::IpAddr,
    pending: gate::Pending,
    gate: &Gate,
    store: Store,
    settings: Arc<ServerSettings>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Error> {
    // Everything up to a proved secret, TLS included, has one deadline.
    let (mut conn, (follow_id, follow_seq)) =
        tokio::time::timeout(settings.handshake_timeout, async {
            let mut conn = Conn::new(open_stream(stream, &settings).await?);
            let position = handshake(&mut conn, &settings, ip, gate).await?;
            Ok::<_, Error>((conn, position))
        })
        .await
        .map_err(|_| Error::Timeout)??;
    drop(pending);

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
    conn: &mut Conn<Stream>,
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
