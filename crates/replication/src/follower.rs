//! The standby's side: follow the active's replication log.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use store::Store;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::protocol::{self, Conn, Kind, Stream, Transcript, Writer};
use crate::{Error, FollowerSettings, LOG_TARGET, messages};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The snapshot spool's file name, in [`FollowerSettings::spool_dir`].
pub const SPOOL_NAME: &str = "replication-snapshot.spool";

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
    // A spool left behind by a run that was killed mid-snapshot holds
    // replicated rows, password hashes and API keys included.
    remove_spool(&settings.spool_dir.join(SPOOL_NAME));
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

async fn connect(settings: &FollowerSettings) -> Result<Stream, Error> {
    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((settings.host.as_str(), settings.port)),
    )
    .await
    .map_err(|_| Error::Timeout)??;
    let _ = stream.set_nodelay(true);
    let sock = socket2::SockRef::from(&stream);
    let _ = sock.set_keepalive(true);
    let Some(tls) = &settings.tls else {
        return Ok(Box::new(stream));
    };
    let connector = tokio_rustls::TlsConnector::from(tls.config.clone());
    let s = tokio::time::timeout(
        CONNECT_TIMEOUT,
        connector.connect(tls.server_name.clone(), stream),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| Error::Protocol(messages::tls_failed(&e.to_string())))?;
    Ok(Box::new(s))
}

/// Remove a spool file, if there is one.
fn remove_spool(path: &Path) {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(target: LOG_TARGET, "{}: {e}", path.display());
    }
}

/// The spool of the snapshot being received. Readable only by irrd-ng's
/// user, and removed whatever way the snapshot ends: applied, refused, or
/// the connection or the follower stopping halfway.
struct Spool {
    path: PathBuf,
    writer: Option<tokio::io::BufWriter<tokio::fs::File>>,
    id: String,
    seq: u64,
}

impl Spool {
    async fn create(path: PathBuf, id: String, seq: u64) -> Result<Spool, Error> {
        remove_spool(&path);
        let mut options = tokio::fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(&path).await.map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                messages::spool_failed(&path.display().to_string(), &e),
            ))
        })?;
        Ok(Spool {
            path,
            writer: Some(tokio::io::BufWriter::with_capacity(1 << 20, file)),
            id,
            seq,
        })
    }

    async fn write(&mut self, rows: &[u8]) -> Result<(), Error> {
        match self.writer.as_mut() {
            Some(w) => Ok(w.write_all(rows).await?),
            None => Err(Error::Protocol("snapshot spool already closed".into())),
        }
    }

    /// Flush and close the file; it stays on disk until the spool is
    /// dropped.
    async fn finish(&mut self) -> Result<(), Error> {
        if let Some(mut w) = self.writer.take() {
            w.flush().await?;
            w.get_mut().sync_all().await?;
        }
        Ok(())
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        self.writer = None;
        remove_spool(&self.path);
    }
}

/// The standby's side of the handshake (see [`protocol`]): prove the
/// secret, then insist on the active's proof before taking anything from
/// it.
async fn handshake(
    conn: &mut Conn<Stream>,
    store: &Store,
    settings: &FollowerSettings,
) -> Result<u64, Error> {
    let mut transcript = Transcript::new();
    let hello = protocol::hello(store::SCHEMA_VERSION, &protocol::nonce()?);
    conn.send(Kind::Hello, &hello).await?;
    transcript.add(Kind::Hello, &hello);
    let (kind, p) = tokio::time::timeout(settings.idle_timeout, conn.recv())
        .await
        .map_err(|_| Error::Timeout)??;
    match kind {
        Kind::Challenge => {}
        Kind::Error => return Err(Error::Remote(messages::remote_text(&p))),
        _ => return Err(Error::Protocol("expected CHALLENGE".into())),
    }
    let proto = protocol::parse_challenge_version(&p)?;
    if proto != protocol::PROTOCOL_VERSION {
        return Err(Error::Protocol(messages::protocol_mismatch(
            proto,
            protocol::PROTOCOL_VERSION,
        )));
    }
    let (_, schema, _) = protocol::parse_challenge(&p)?;
    if schema != store::SCHEMA_VERSION {
        return Err(Error::Protocol(messages::schema_mismatch(
            schema,
            store::SCHEMA_VERSION,
        )));
    }
    transcript.add(Kind::Challenge, &p);
    let s = store.clone();
    let (follow_id, follow_seq) = blocking(move || s.replication_state())
        .await?
        .follow
        .unwrap_or_default();
    let body = Writer::default().str(&follow_id).u64(follow_seq).0;
    transcript.add(Kind::Auth, &body);
    let proof = transcript.standby_proof(&settings.key);
    conn.send(Kind::Auth, &Writer(body).bytes(&proof).0).await?;
    transcript.add_proof(&proof);
    let (kind, p) = tokio::time::timeout(settings.idle_timeout, conn.recv())
        .await
        .map_err(|_| Error::Timeout)??;
    match kind {
        Kind::Accept => {}
        Kind::Error => return Err(Error::Remote(messages::remote_text(&p))),
        _ => return Err(Error::Protocol("expected ACCEPT".into())),
    }
    let accept = protocol::parse_accept(&p)?;
    if !protocol::constant_time_eq(&accept, &transcript.active_proof(&settings.key)) {
        return Err(Error::Protocol(messages::AUTH_FAILED.into()));
    }
    transcript.add(Kind::Accept, &p);
    conn.set_key(transcript.session_key(&settings.key));
    Ok(follow_seq)
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
    let follow_seq = handshake(&mut conn, store, settings).await?;
    tracing::info!(
        target: LOG_TARGET,
        "{}",
        messages::connected(&settings.host, settings.port, &format!("after log entry {follow_seq}"))
    );

    let spool_path = settings.spool_dir.join(SPOOL_NAME);
    let mut spool: Option<Spool> = None;
    loop {
        let (kind, p) = tokio::time::timeout(settings.idle_timeout, conn.recv())
            .await
            .map_err(|_| Error::Timeout)??;
        match kind {
            Kind::Heartbeat => {}
            Kind::Error => return Err(Error::Remote(messages::remote_text(&p))),
            Kind::SnapshotBegin => {
                let (id, seq) = protocol::parse_position(&p)?;
                tracing::info!(target: LOG_TARGET, "{}", messages::snapshot_loading(&id, seq));
                // Any half-received one is dropped, and its file with it.
                drop(spool.take());
                spool = Some(Spool::create(spool_path.clone(), id, seq).await?);
            }
            Kind::SnapshotRows => {
                let Some(sp) = spool.as_mut() else {
                    return Err(Error::Protocol("snapshot rows outside a snapshot".into()));
                };
                sp.write(&p).await?;
            }
            Kind::SnapshotEnd => {
                let Some(mut sp) = spool.take() else {
                    return Err(Error::Protocol("snapshot end outside a snapshot".into()));
                };
                sp.finish().await?;
                let started = Instant::now();
                let (s, path, id, seq) = (store.clone(), sp.path.clone(), sp.id.clone(), sp.seq);
                let applied = blocking(move || s.apply_replication_snapshot(&id, seq, &path)).await;
                drop(sp);
                let rows = applied?;
                *progressed = true;
                tracing::info!(
                    target: LOG_TARGET,
                    "{}",
                    messages::snapshot_loaded(rows, started.elapsed().as_secs_f64())
                );
            }
            Kind::Entries => {
                let (id, entries) = protocol::parse_entries(&p)?;
                let s = store.clone();
                blocking(move || s.apply_replication_entries(&id, entries)).await?;
                *progressed = true;
            }
            Kind::Hello | Kind::Challenge | Kind::Auth | Kind::Accept => {
                return Err(Error::Protocol("unexpected handshake frame".into()));
            }
        }
    }
}
