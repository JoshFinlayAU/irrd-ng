//! The standby's side: follow the active's replication log.

use std::sync::Arc;
use std::time::{Duration, Instant};

use store::Store;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::protocol::{self, Conn, Kind, Reader, Writer};
use crate::{Error, FollowerSettings, LOG_TARGET, messages};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SPOOL_NAME: &str = "replication-snapshot.spool";

async fn blocking<R: Send + 'static>(
    f: impl FnOnce() -> Result<R, store::StoreError> + Send + 'static,
) -> Result<R, Error> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::Protocol(e.to_string()))?
        .map_err(Error::Store)
}

/// Follow the active until `shutdown` turns true, reconnecting with
/// backoff whenever the stream ends.
pub async fn run(
    store: Store,
    settings: Arc<FollowerSettings>,
    mut shutdown: watch::Receiver<bool>,
) {
    tracing::info!(target: LOG_TARGET, "{}", messages::following(&settings.host, settings.port));
    let mut backoff = Duration::from_secs(1);
    loop {
        let mut progressed = false;
        let r = tokio::select! {
            r = session(&store, &settings, &mut progressed) => r,
            _ = shutdown.changed() => break,
        };
        if progressed {
            backoff = Duration::from_secs(1);
        }
        if let Err(e) = r {
            tracing::warn!(
                target: LOG_TARGET,
                "{}",
                messages::session_failed(&settings.host, settings.port, &e.to_string(), backoff.as_secs())
            );
        }
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = shutdown.changed() => break,
        }
        backoff = (backoff * 2).min(settings.max_backoff.max(Duration::from_secs(1)));
    }
    tracing::info!(target: LOG_TARGET, "{}", messages::STOPPED);
}

async fn connect(settings: &FollowerSettings) -> Result<TcpStream, Error> {
    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((settings.host.as_str(), settings.port)),
    )
    .await
    .map_err(|_| Error::Timeout)??;
    let _ = stream.set_nodelay(true);
    let sock = socket2::SockRef::from(&stream);
    let _ = sock.set_keepalive(true);
    Ok(stream)
}

/// One connection: handshake, then apply what the active sends until the
/// stream fails.
async fn session(
    store: &Store,
    settings: &FollowerSettings,
    progressed: &mut bool,
) -> Result<(), Error> {
    let stream = connect(settings).await?;
    let mut conn = Conn::new(stream);
    let cn = protocol::nonce()?;
    conn.send(Kind::Hello, &protocol::hello(store::SCHEMA_VERSION, &cn))
        .await?;
    let (kind, p) = tokio::time::timeout(settings.idle_timeout, conn.recv())
        .await
        .map_err(|_| Error::Timeout)??;
    match kind {
        Kind::Challenge => {}
        Kind::Error => return Err(Error::Remote(String::from_utf8_lossy(&p).into_owned())),
        _ => return Err(Error::Protocol("expected CHALLENGE".into())),
    }
    let mut r = Reader(&p);
    let (proto, schema, sn, proof) = (r.u32()?, r.u32()?, r.array32()?, r.array32()?);
    if proto != protocol::PROTOCOL_VERSION {
        return Err(Error::Protocol(messages::protocol_mismatch(
            proto,
            protocol::PROTOCOL_VERSION,
        )));
    }
    if schema != store::SCHEMA_VERSION {
        return Err(Error::Protocol(messages::schema_mismatch(
            schema,
            store::SCHEMA_VERSION,
        )));
    }
    if !protocol::constant_time_eq(&proof, &protocol::server_proof(&settings.secret, &cn, &sn)) {
        return Err(Error::Protocol(messages::AUTH_FAILED.into()));
    }
    let s = store.clone();
    let (follow_id, follow_seq) = blocking(move || s.replication_state())
        .await?
        .follow
        .unwrap_or_default();
    let auth = Writer::default()
        .bytes(&protocol::client_proof(&settings.secret, &cn, &sn))
        .str(&follow_id)
        .u64(follow_seq)
        .0;
    conn.send(Kind::Auth, &auth).await?;
    conn.set_key(protocol::session_key(&settings.secret, &cn, &sn));
    tracing::info!(
        target: LOG_TARGET,
        "{}",
        messages::connected(&settings.host, settings.port, &format!("after log entry {follow_seq}"))
    );

    let spool_path = settings.spool_dir.join(SPOOL_NAME);
    let mut spool: Option<(tokio::io::BufWriter<tokio::fs::File>, String, u64)> = None;
    loop {
        let (kind, p) = tokio::time::timeout(settings.idle_timeout, conn.recv())
            .await
            .map_err(|_| Error::Timeout)??;
        match kind {
            Kind::Heartbeat => {}
            Kind::Error => return Err(Error::Remote(String::from_utf8_lossy(&p).into_owned())),
            Kind::SnapshotBegin => {
                let mut r = Reader(&p);
                let (id, seq) = (r.str()?, r.u64()?);
                tracing::info!(target: LOG_TARGET, "{}", messages::snapshot_loading(&id, seq));
                let f = tokio::fs::File::create(&spool_path).await?;
                spool = Some((tokio::io::BufWriter::with_capacity(1 << 20, f), id, seq));
            }
            Kind::SnapshotRows => {
                let Some((w, _, _)) = spool.as_mut() else {
                    return Err(Error::Protocol("snapshot rows outside a snapshot".into()));
                };
                w.write_all(&p).await?;
            }
            Kind::SnapshotEnd => {
                let Some((mut w, id, seq)) = spool.take() else {
                    return Err(Error::Protocol("snapshot end outside a snapshot".into()));
                };
                w.flush().await?;
                w.get_mut().sync_all().await?;
                drop(w);
                let started = Instant::now();
                let (s, path) = (store.clone(), spool_path.clone());
                let applied = blocking(move || s.apply_replication_snapshot(&id, seq, &path)).await;
                let _ = tokio::fs::remove_file(&spool_path).await;
                let rows = applied?;
                *progressed = true;
                tracing::info!(
                    target: LOG_TARGET,
                    "{}",
                    messages::snapshot_loaded(rows, started.elapsed().as_secs_f64())
                );
            }
            Kind::Entries => {
                let mut r = Reader(&p);
                let id = r.str()?;
                let n = r.u32()?;
                let mut entries = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let seq = r.u64()?;
                    entries.push((seq, r.blob()?.to_vec()));
                }
                let s = store.clone();
                blocking(move || s.apply_replication_entries(&id, entries)).await?;
                *progressed = true;
            }
            Kind::Hello | Kind::Challenge | Kind::Auth => {
                return Err(Error::Protocol("unexpected handshake frame".into()));
            }
        }
    }
}
