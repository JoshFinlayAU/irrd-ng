//! The handshake and what an unauthenticated peer can do: the standby
//! proves the secret first and the active proves nothing to a peer that
//! has not; changing any handshake frame on the way fails it; versions are
//! refused with a message saying so; unauthenticated connections are
//! capped, timed out and locked out after repeated failures; and the
//! standby's snapshot spool is private and never outlives the snapshot.

#![allow(clippy::unwrap_used, clippy::expect_used, unreachable_pub)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use replication::{FollowerSettings, ServerSettings, SharedKey, follower, messages, server};
use store::{
    JournalEntryOrigin, Json, NewRpslObject, RoutePreferenceStatus, RpkiStatus, ScopeFilterStatus,
    SourceSettings, Store, StoreOptions, StoreSettings,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "irrd-ng-replication-hs-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("temp dir");
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Log lines of every test in this binary.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn count(&self, needle: &str) -> usize {
        String::from_utf8_lossy(&self.0.lock().unwrap())
            .matches(needle)
            .count()
    }
}

fn log() -> &'static Captured {
    static LOG: OnceLock<Captured> = OnceLock::new();
    LOG.get_or_init(|| {
        let log = Captured::default();
        let writer = log.clone();
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || writer.clone())
            .try_init();
        log
    })
}

async fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let started = Instant::now();
    while !f() {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

const SECRET: &[u8] = b"a shared secret of some length";

fn key() -> SharedKey {
    static KEY: OnceLock<SharedKey> = OnceLock::new();
    KEY.get_or_init(|| SharedKey::derive(SECRET).expect("derive"))
        .clone()
}

fn open(dir: &TempDir, standby: bool) -> Store {
    let settings = StoreSettings {
        sources: [(
            "TEST".to_owned(),
            SourceSettings {
                keep_journal: true,
                ..Default::default()
            },
        )]
        .into_iter()
        .collect(),
        readonly_standby: standby,
        ..StoreSettings::default()
    };
    let mut o = StoreOptions::new(dir.0.join("store"));
    o.initial_map_size = 64 << 20;
    Store::open(&o, settings).expect("open store")
}

fn upsert(store: &Store, pk: &str, text: String) {
    let o = NewRpslObject {
        rpsl_pk: pk.to_owned(),
        source: "TEST".to_owned(),
        object_class: "as-set".to_owned(),
        parsed_data: Json::canonical(r#"{"mnt-by": ["MNT-TEST"], "source": "TEST"}"#)
            .expect("json"),
        object_text: text,
        ip_first: None,
        ip_last: None,
        prefix: None,
        prefix_length: None,
        asn_first: None,
        asn_last: None,
        rpki_status: RpkiStatus::NotFound,
        scopefilter_status: ScopeFilterStatus::InScope,
        route_preference_status: RoutePreferenceStatus::Visible,
    };
    store
        .write(move |tx| {
            tx.upsert_rpsl_object(&o, JournalEntryOrigin::AuthChange, None, None)
                .map(|_| ())
        })
        .expect("write");
}

/// An active with a few objects and its log enabled.
fn active(dir: &TempDir) -> Store {
    let store = open(dir, false);
    store.enable_replication_log().expect("enable");
    for i in 0..3 {
        upsert(
            &store,
            &format!("AS-SET{i}"),
            format!("as-set: AS-SET{i}\n"),
        );
    }
    store
}

struct Running {
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
    }
}

fn start_server(store: &Store, tune: impl FnOnce(&mut ServerSettings)) -> (Running, u16) {
    let mut s = ServerSettings::new("127.0.0.1", 0, key());
    s.heartbeat = Duration::from_millis(200);
    tune(&mut s);
    let listener = server::bind(&s).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(server::serve(listener, store.clone(), Arc::new(s), rx));
    (Running { shutdown: tx, task }, port)
}

fn start_follower(store: &Store, port: u16, spool: &TempDir) -> Running {
    let mut s = FollowerSettings::new("127.0.0.1", port, key(), &spool.0);
    s.idle_timeout = Duration::from_secs(2);
    s.max_backoff = Duration::from_secs(1);
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(follower::run(store.clone(), Arc::new(s), rx));
    Running { shutdown: tx, task }
}

async fn converge(active: &Store, standby: &Store) {
    let started = Instant::now();
    loop {
        let a = active.replication_state().expect("state");
        let s = standby.replication_state().expect("state");
        if s.follow == Some((a.id.clone().expect("log enabled"), a.last_seq)) {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "standby did not converge: active {a:?}, standby {s:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// Raw frames, as the protocol module documents them.
const HELLO: u8 = 1;
const CHALLENGE: u8 = 2;
const AUTH: u8 = 3;
const ERROR: u8 = 4;
const ACCEPT: u8 = 5;
const SNAPSHOT_ROWS: u8 = 11;

/// One frame: the kind byte and everything after it (payload and, once
/// authenticated, the tag).
async fn read_frame(s: &mut (impl AsyncReadExt + Unpin)) -> std::io::Result<(u8, Vec<u8>)> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut buf).await?;
    let kind = buf.remove(0);
    Ok((kind, buf))
}

async fn write_frame(
    s: &mut (impl AsyncWriteExt + Unpin),
    kind: u8,
    body: &[u8],
) -> std::io::Result<()> {
    let mut out = ((body.len() + 1) as u32).to_be_bytes().to_vec();
    out.push(kind);
    out.extend_from_slice(body);
    s.write_all(&out).await
}

fn hello(version: u32) -> Vec<u8> {
    let mut p = b"IRRDNG-REPL".to_vec();
    p.extend_from_slice(&version.to_be_bytes());
    p.extend_from_slice(&store::SCHEMA_VERSION.to_be_bytes());
    p.extend_from_slice(&[9; 32]);
    p
}

/// Whether the other end closes the connection within `within`, without
/// sending anything.
async fn closed_silently(s: &mut TcpStream, within: Duration) -> bool {
    let mut b = [0u8; 1];
    matches!(
        tokio::time::timeout(within, s.read(&mut b)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

async fn connect(port: u16) -> TcpStream {
    TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect")
}

/// A peer that does not know the secret gets the active's nonce and
/// nothing else: no proof in `CHALLENGE`, and an `ERROR`, never `ACCEPT`,
/// for a wrong proof. One that never sends `AUTH` is closed at the
/// handshake deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn active_proves_nothing_to_an_unauthenticated_peer() {
    log();
    let adir = TempDir::new("noproof");
    let store = active(&adir);
    let (srv, port) = start_server(&store, |s| s.handshake_timeout = Duration::from_millis(800));

    let mut c = connect(port).await;
    write_frame(&mut c, HELLO, &hello(2)).await.expect("hello");
    let (kind, challenge) = read_frame(&mut c).await.expect("challenge");
    assert_eq!(kind, CHALLENGE);
    // Protocol version, schema version, nonce: nothing derived from the
    // secret.
    assert_eq!(challenge.len(), 4 + 4 + 32);
    assert_eq!(challenge[..4], 2u32.to_be_bytes());
    let mut auth = vec![0, 0];
    auth.extend_from_slice(&0u64.to_be_bytes());
    auth.extend_from_slice(&[0xab; 32]);
    write_frame(&mut c, AUTH, &auth).await.expect("auth");
    let (kind, text) = read_frame(&mut c).await.expect("reply");
    assert_eq!(kind, ERROR);
    assert_eq!(text, messages::AUTH_FAILED.as_bytes());
    assert!(closed_silently(&mut c, Duration::from_secs(2)).await);

    // Silent after CHALLENGE: closed at the deadline, with nothing more.
    let mut c = connect(port).await;
    write_frame(&mut c, HELLO, &hello(2)).await.expect("hello");
    let (kind, _) = read_frame(&mut c).await.expect("challenge");
    assert_eq!(kind, CHALLENGE);
    let started = Instant::now();
    assert!(closed_silently(&mut c, Duration::from_secs(5)).await);
    assert!(started.elapsed() < Duration::from_secs(3));

    // Silent from the start: the same deadline.
    let mut c = connect(port).await;
    assert!(closed_silently(&mut c, Duration::from_secs(5)).await);
    srv.stop().await;
}

/// The standby sends its proof before it has seen any from the active,
/// and refuses an active whose proof is wrong without applying anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standby_proves_first_and_checks_the_active() {
    log();
    let fake = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = fake.local_addr().expect("addr").port();
    let sdir = TempDir::new("fake-active");
    let standby = open(&sdir, true);
    let fol = start_follower(&standby, port, &sdir);

    for _ in 0..2 {
        let (mut s, _) = fake.accept().await.expect("accept");
        let (kind, _) = read_frame(&mut s).await.expect("hello");
        assert_eq!(kind, HELLO);
        let mut challenge = 2u32.to_be_bytes().to_vec();
        challenge.extend_from_slice(&store::SCHEMA_VERSION.to_be_bytes());
        challenge.extend_from_slice(&[3; 32]);
        write_frame(&mut s, CHALLENGE, &challenge)
            .await
            .expect("challenge");
        // The standby answers a challenge that carries no proof with its
        // own.
        let (kind, auth) = read_frame(&mut s).await.expect("auth");
        assert_eq!(kind, AUTH);
        assert!(auth.len() >= 32 + 2 + 8);
        // A made-up proof: the standby drops the connection rather than
        // read anything after it.
        write_frame(&mut s, ACCEPT, &[0x5a; 32])
            .await
            .expect("accept");
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut b))
            .await
            .expect("closed in time")
            .unwrap_or(0);
        assert_eq!(n, 0);
    }
    fol.stop().await;
    assert_eq!(standby.replication_state().expect("state").follow, None);
    assert!(log().count(messages::AUTH_FAILED) >= 2);
}

/// What the proxy between a standby and an active does to the handshake.
#[derive(Clone, Copy, Debug, Default)]
struct Tamper {
    hello: bool,
    challenge: bool,
    auth_position: bool,
    accept: bool,
    /// Stop forwarding after the first `SNAPSHOT_ROWS` frame, and hold the
    /// connection open until told to drop it.
    pause_after_rows: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Seen {
    /// A frame from the active, by kind.
    FromActive(u8),
    Paused,
}

/// A proxy for one standby at a time, forwarding frame by frame. Returns
/// its port, what it sees, and a switch that drops every connection.
async fn proxy(
    active_port: u16,
    tamper: Tamper,
) -> (u16, mpsc::UnboundedReceiver<Seen>, watch::Sender<u64>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (seen_tx, seen_rx) = mpsc::unbounded_channel();
    let (cut_tx, cut_rx) = watch::channel(0u64);
    tokio::spawn(async move {
        loop {
            let Ok((c, _)) = listener.accept().await else {
                return;
            };
            let (seen, mut cut) = (seen_tx.clone(), cut_rx.clone());
            cut.mark_unchanged();
            tokio::spawn(async move {
                tokio::select! {
                    _ = relay(c, active_port, tamper, seen) => {}
                    _ = cut.changed() => {}
                }
            });
        }
    });
    (port, seen_rx, cut_tx)
}

async fn relay(
    mut c: TcpStream,
    active_port: u16,
    tamper: Tamper,
    seen: mpsc::UnboundedSender<Seen>,
) -> std::io::Result<()> {
    let mut a = TcpStream::connect(("127.0.0.1", active_port)).await?;
    let (kind, mut p) = read_frame(&mut c).await?;
    if tamper.hello {
        // Ignored by the parser, but part of the transcript.
        p.push(0);
    }
    write_frame(&mut a, kind, &p).await?;
    let (kind, mut p) = read_frame(&mut a).await?;
    let _ = seen.send(Seen::FromActive(kind));
    if tamper.challenge {
        p.push(0);
    }
    write_frame(&mut c, kind, &p).await?;
    let (kind, mut p) = read_frame(&mut c).await?;
    if tamper.auth_position && p.len() > 32 {
        // The last byte of the log sequence, just before the proof.
        let i = p.len() - 33;
        p[i] ^= 1;
    }
    write_frame(&mut a, kind, &p).await?;
    let (mut ar, mut aw) = a.into_split();
    let (mut cr, mut cw) = c.into_split();
    let up = tokio::spawn(async move { tokio::io::copy(&mut cr, &mut aw).await });
    let mut first = true;
    let r = async {
        loop {
            let (kind, mut p) = read_frame(&mut ar).await?;
            let _ = seen.send(Seen::FromActive(kind));
            if first && kind == ACCEPT && tamper.accept {
                p[0] ^= 1;
            }
            first = false;
            write_frame(&mut cw, kind, &p).await?;
            if tamper.pause_after_rows && kind == SNAPSHOT_ROWS {
                let _ = seen.send(Seen::Paused);
                std::future::pending::<()>().await;
            }
        }
    }
    .await;
    up.abort();
    r
}

/// Changing any part of the handshake on the way fails it, including the
/// parts the old protocol left out of the proofs (trailing bytes, the log
/// position in `AUTH`), and a tampered `ACCEPT` is refused by the standby.
/// The same proxy without tampering lets the standby converge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_handshakes_fail() {
    log();
    let adir = TempDir::new("tamper-active");
    let store = active(&adir);

    // Through an honest proxy: converges.
    let (srv, port) = start_server(&store, |_| {});
    let (pport, _, _cut) = proxy(port, Tamper::default()).await;
    let sdir = TempDir::new("tamper-honest");
    let standby = open(&sdir, true);
    let fol = start_follower(&standby, pport, &sdir);
    converge(&store, &standby).await;
    fol.stop().await;
    srv.stop().await;

    let cases = [
        Tamper {
            hello: true,
            ..Tamper::default()
        },
        Tamper {
            challenge: true,
            ..Tamper::default()
        },
        Tamper {
            auth_position: true,
            ..Tamper::default()
        },
    ];
    for (i, tamper) in cases.into_iter().enumerate() {
        // A server of its own, so the failures do not add up to a lockout.
        let (srv, port) = start_server(&store, |_| {});
        let (pport, mut seen, _cut) = proxy(port, tamper).await;
        let sdir = TempDir::new("tampered");
        let standby = open(&sdir, true);
        let fol = start_follower(&standby, pport, &sdir);
        // CHALLENGE, then the refusal of the standby's proof.
        let mut kinds = Vec::new();
        while kinds.len() < 2 {
            let Some(Seen::FromActive(k)) =
                tokio::time::timeout(Duration::from_secs(10), seen.recv())
                    .await
                    .expect("frames in time")
            else {
                continue;
            };
            kinds.push(k);
        }
        fol.stop().await;
        srv.stop().await;
        assert_eq!(kinds, [CHALLENGE, ERROR], "case {i}: {tamper:?}");
        assert_eq!(
            standby.replication_state().expect("state").follow,
            None,
            "case {i}"
        );
    }

    // The active's proof altered: the standby takes nothing after it.
    let (srv, port) = start_server(&store, |_| {});
    let (pport, mut seen, _cut) = proxy(
        port,
        Tamper {
            accept: true,
            ..Tamper::default()
        },
    )
    .await;
    let sdir = TempDir::new("tampered-accept");
    let standby = open(&sdir, true);
    let before = log().count(messages::AUTH_FAILED);
    let fol = start_follower(&standby, pport, &sdir);
    let mut accepts = 0;
    while accepts < 2 {
        if let Some(Seen::FromActive(ACCEPT)) =
            tokio::time::timeout(Duration::from_secs(10), seen.recv())
                .await
                .expect("frames in time")
        {
            accepts += 1;
        }
    }
    wait_until("the standby's refusal", || {
        log().count(messages::AUTH_FAILED) > before
    })
    .await;
    fol.stop().await;
    srv.stop().await;
    assert_eq!(standby.replication_state().expect("state").follow, None);
}

/// Old and new protocol versions refuse each other, and say why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protocol_versions_refuse_each_other() {
    log();
    // A version 1 standby at this active.
    let adir = TempDir::new("version-active");
    let store = active(&adir);
    let (srv, port) = start_server(&store, |_| {});
    let mut c = connect(port).await;
    write_frame(&mut c, HELLO, &hello(1)).await.expect("hello");
    let (kind, text) = read_frame(&mut c).await.expect("reply");
    assert_eq!(kind, ERROR);
    assert_eq!(
        String::from_utf8(text).expect("utf-8"),
        messages::protocol_mismatch(2, 1)
    );
    srv.stop().await;

    // This standby at a version 1 active. A real one refuses the HELLO
    // with its own message, which the standby reports as sent; one that
    // answered anyway is refused on the version alone.
    let fake = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = fake.local_addr().expect("addr").port();
    let sdir = TempDir::new("version-standby");
    let standby = open(&sdir, true);
    let fol = start_follower(&standby, port, &sdir);
    let (mut s, _) = fake.accept().await.expect("accept");
    let (kind, p) = read_frame(&mut s).await.expect("hello");
    assert_eq!(kind, HELLO);
    assert_eq!(p[11..15], 2u32.to_be_bytes());
    write_frame(
        &mut s,
        ERROR,
        b"replication protocol 1 on the active and 2 on the standby",
    )
    .await
    .expect("error");
    let (mut s, _) = fake.accept().await.expect("accept");
    read_frame(&mut s).await.expect("hello");
    // A version 1 CHALLENGE also carried the active's proof.
    let mut challenge = 1u32.to_be_bytes().to_vec();
    challenge.extend_from_slice(&store::SCHEMA_VERSION.to_be_bytes());
    challenge.extend_from_slice(&[3; 64]);
    write_frame(&mut s, CHALLENGE, &challenge)
        .await
        .expect("challenge");
    let mismatch = messages::protocol_mismatch(1, 2);
    wait_until("the version refusal", || log().count(&mismatch) >= 1).await;
    // The standby sent nothing after HELLO.
    assert!(closed_silently(&mut s, Duration::from_secs(5)).await);
    fol.stop().await;
    assert!(log().count("replication protocol 1 on the active and 2 on the standby") >= 2);
    assert_eq!(standby.replication_state().expect("state").follow, None);
}

/// Connections that have not proved the secret are capped, overall and
/// per address, and an address that keeps failing is locked out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unauthenticated_connections_are_limited() {
    log();
    let adir = TempDir::new("limits");
    let store = active(&adir);

    for per_ip in [true, false] {
        let (srv, port) = start_server(&store, |s| {
            if per_ip {
                s.max_unauthenticated_per_ip = 2;
            } else {
                s.max_unauthenticated = 2;
                s.max_unauthenticated_per_ip = 100;
            }
        });
        let mut held = vec![connect(port).await, connect(port).await];
        // Give the server time to count both.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut refused = connect(port).await;
        assert!(
            closed_silently(&mut refused, Duration::from_secs(2)).await,
            "per_ip {per_ip}"
        );
        // A slot frees up when one of them goes.
        drop(held.pop());
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut c = connect(port).await;
        write_frame(&mut c, HELLO, &hello(2)).await.expect("hello");
        let (kind, _) = read_frame(&mut c).await.expect("challenge");
        assert_eq!(kind, CHALLENGE, "per_ip {per_ip}");
        drop(held);
        srv.stop().await;
    }
    assert!(log().count(messages::TOO_MANY_PENDING_PEER) >= 1);
    assert!(log().count(messages::TOO_MANY_PENDING) >= 1);

    // Five wrong proofs, then the address is refused before CHALLENGE, even
    // with the right secret.
    let (srv, port) = start_server(&store, |_| {});
    for _ in 0..5 {
        let mut c = connect(port).await;
        write_frame(&mut c, HELLO, &hello(2)).await.expect("hello");
        let (kind, _) = read_frame(&mut c).await.expect("challenge");
        assert_eq!(kind, CHALLENGE);
        let mut auth = vec![0, 0];
        auth.extend_from_slice(&0u64.to_be_bytes());
        auth.extend_from_slice(&[1; 32]);
        write_frame(&mut c, AUTH, &auth).await.expect("auth");
        let (kind, _) = read_frame(&mut c).await.expect("error");
        assert_eq!(kind, ERROR);
    }
    let mut c = connect(port).await;
    assert!(closed_silently(&mut c, Duration::from_secs(2)).await);
    let sdir = TempDir::new("locked-out");
    let standby = open(&sdir, true);
    let fol = start_follower(&standby, port, &sdir);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    fol.stop().await;
    assert_eq!(standby.replication_state().expect("state").follow, None);
    assert!(log().count("failed replication authentication 5 times") >= 1);
    srv.stop().await;
}

/// The spool is created 0600, and removed when a snapshot is cut off
/// halfway, by the connection or by the follower stopping. A stale one, or
/// a symbolic link in its place, is removed at start without following it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spool_is_private_and_cleaned_up() {
    log();
    let adir = TempDir::new("spool-active");
    let store = active(&adir);
    // Enough rows for several SNAPSHOT_ROWS frames.
    let big = "x".repeat(200 << 10);
    for i in 0..20 {
        upsert(&store, &format!("AS-BIG{i}"), big.clone());
    }
    let (srv, port) = start_server(&store, |_| {});
    let (pport, mut seen, cut) = proxy(
        port,
        Tamper {
            pause_after_rows: true,
            ..Tamper::default()
        },
    )
    .await;

    let sdir = TempDir::new("spool-standby");
    let spool = sdir.0.join(follower::SPOOL_NAME);
    // A stale spool from an earlier run, as a link to a file elsewhere.
    let target = TempDir::new("spool-target");
    let target_file = target.0.join("precious");
    std::fs::write(&target_file, b"keep me").expect("write");
    std::os::unix::fs::symlink(&target_file, &spool).expect("symlink");

    let standby = open(&sdir, true);

    // Cut off by the connection.
    let fol = start_follower(&standby, pport, &sdir);
    wait_for_pause(&mut seen).await;
    // The proxy has forwarded the rows; the follower may not have read them
    // yet on a slow machine.
    wait_until("the spool", || {
        std::fs::symlink_metadata(&spool).is_ok_and(|m| m.file_type().is_file())
    })
    .await;
    assert_eq!(std::fs::read(&target_file).expect("read"), b"keep me");
    let meta = std::fs::symlink_metadata(&spool).expect("spool exists");
    assert!(meta.file_type().is_file(), "a file, not the old link");
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    cut.send_modify(|n| *n += 1);
    wait_until("the spool's removal", || {
        std::fs::symlink_metadata(&spool).is_err()
    })
    .await;

    // Cut off by the follower stopping.
    wait_for_pause(&mut seen).await;
    wait_until("the second spool", || spool.exists()).await;
    fol.stop().await;
    assert!(!spool.exists());
    cut.send_modify(|n| *n += 1);

    // A spool left by a killed process is removed at start.
    std::fs::write(&spool, b"stale rows").expect("write");
    let fol = start_follower(&standby, port, &sdir);
    converge(&store, &standby).await;
    assert!(!spool.exists());
    fol.stop().await;
    srv.stop().await;
    assert_eq!(std::fs::read(&target_file).expect("read"), b"keep me");
}

async fn wait_for_pause(seen: &mut mpsc::UnboundedReceiver<Seen>) {
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(20), seen.recv())
            .await
            .expect("paused in time")
            .expect("proxy running");
        if ev == Seen::Paused {
            return;
        }
    }
}
