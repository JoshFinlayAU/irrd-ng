//! TLS on the replication stream: a standby that trusts the active's CA or
//! has its certificate pinned converges; a wrong CA, a wrong pin or a wrong
//! server name gets nothing; and a plaintext end never talks to a TLS end
//! in either direction. Certificates are generated here, at test time.

#![allow(clippy::unwrap_used, clippy::expect_used, unreachable_pub)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use replication::tls::{self, Trust};
use replication::{FollowerSettings, ServerSettings, follower, server};
use store::{
    JournalEntryOrigin, Json, NewRpslObject, RoutePreferenceStatus, RpkiStatus, ScopeFilterStatus,
    SourceSettings, Store, StoreOptions, StoreSettings,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "irrd-ng-replication-tls-{tag}-{}-{n}",
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

    /// Wait until `needle` has been logged `n` times in all.
    async fn wait_for(&self, needle: &str, n: usize) {
        let started = Instant::now();
        while self.count(needle) < n {
            assert!(
                started.elapsed() < Duration::from_secs(15),
                "{needle:?} not logged {n} times"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

const SECRET: &[u8] = b"a shared secret of some length";

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

fn upsert(store: &Store, pk: &str) {
    let o = NewRpslObject {
        rpsl_pk: pk.to_owned(),
        source: "TEST".to_owned(),
        object_class: "as-set".to_owned(),
        parsed_data: Json::canonical(r#"{"mnt-by": ["MNT-TEST"], "source": "TEST"}"#)
            .expect("json"),
        object_text: format!("as-set: {pk}\n"),
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

fn object_count(store: &Store) -> u64 {
    store
        .read()
        .expect("read")
        .view()
        .object_count()
        .expect("n")
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

fn start_server(store: &Store, tls: Option<Arc<rustls::ServerConfig>>) -> (Running, u16) {
    let mut s = ServerSettings::new("127.0.0.1", 0, SECRET);
    s.heartbeat = Duration::from_millis(200);
    s.tls = tls;
    let listener = server::bind(&s).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(server::serve(listener, store.clone(), Arc::new(s), rx));
    (Running { shutdown: tx, task }, port)
}

fn start_follower(
    store: &Store,
    port: u16,
    spool: &TempDir,
    tls: Option<tls::ClientTls>,
) -> Running {
    let mut s = FollowerSettings::new("127.0.0.1", port, SECRET, &spool.0);
    s.idle_timeout = Duration::from_secs(2);
    s.max_backoff = Duration::from_secs(1);
    s.tls = tls;
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(follower::run(store.clone(), Arc::new(s), rx));
    Running { shutdown: tx, task }
}

/// A CA, and a certificate it signed for `localhost` and 127.0.0.1, written
/// as PEM files.
struct Pki {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    cert_der: Vec<u8>,
}

fn pki(dir: &Path, tag: &str) -> Pki {
    let ca_key = KeyPair::generate().expect("key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca");
    let issuer = Issuer::new(ca_params, ca_key);
    let key = KeyPair::generate().expect("key");
    let cert = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
        .expect("params")
        .signed_by(&key, &issuer)
        .expect("cert");
    let out = Pki {
        ca: dir.join(format!("{tag}-ca.pem")),
        cert: dir.join(format!("{tag}-cert.pem")),
        key: dir.join(format!("{tag}-key.pem")),
        cert_der: cert.der().to_vec(),
    };
    std::fs::write(&out.ca, ca_cert.pem()).expect("write");
    std::fs::write(&out.cert, cert.pem()).expect("write");
    std::fs::write(&out.key, key.serialize_pem()).expect("write");
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replication_over_tls() {
    let log = Captured::default();
    let writer = log.clone();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .try_init();

    let certs = TempDir::new("certs");
    let good = pki(&certs.0, "good");
    let other = pki(&certs.0, "other");

    let adir = TempDir::new("active");
    let active = open(&adir, false);
    active.enable_replication_log().expect("enable");
    upsert(&active, "AS-ONE");
    let server_tls = tls::server_config(&good.cert, &good.key).expect("server tls");
    let (srv, port) = start_server(&active, Some(server_tls));

    // Trusting the CA, with the name checked against the host.
    let sdir = TempDir::new("ca");
    let standby = open(&sdir, true);
    let ca = tls::client_config(Trust::Ca(good.ca.clone()), "127.0.0.1").expect("client tls");
    let fol = start_follower(&standby, port, &sdir, Some(ca));
    converge(&active, &standby).await;
    upsert(&active, "AS-TWO");
    converge(&active, &standby).await;
    assert_eq!(object_count(&standby), 2);
    fol.stop().await;

    // Pinning the certificate. The pin is all that is checked, so the name
    // does not matter.
    let pdir = TempDir::new("pin");
    let pinned = open(&pdir, true);
    let pin = tls::client_config(Trust::Pin(tls::fingerprint(&good.cert_der)), "irrd.invalid")
        .expect("client tls");
    let fol = start_follower(&pinned, port, &pdir, Some(pin));
    converge(&active, &pinned).await;
    assert_eq!(object_count(&pinned), 2);
    fol.stop().await;

    // Wrong certificates: another CA, another pin, a name the certificate
    // is not for. Each fails the TLS handshake and replicates nothing.
    let wrong = [
        tls::client_config(Trust::Ca(other.ca.clone()), "127.0.0.1"),
        tls::client_config(Trust::Pin(tls::fingerprint(&other.cert_der)), "127.0.0.1"),
        tls::client_config(Trust::Ca(good.ca.clone()), "irrd.invalid"),
    ];
    for (i, client) in wrong.into_iter().enumerate() {
        let before = log.count("TLS handshake failed");
        let wdir = TempDir::new("wrong");
        let refused = open(&wdir, true);
        let fol = start_follower(&refused, port, &wdir, Some(client.expect("client tls")));
        // Logged by the standby and by the active.
        log.wait_for("TLS handshake failed", before + 2).await;
        fol.stop().await;
        assert_eq!(
            refused.replication_state().expect("state").follow,
            None,
            "case {i}"
        );
        assert_eq!(object_count(&refused), 0, "case {i}");
    }
    assert!(log.count("does not match ng_replication.tls_pin") >= 1);

    // A plaintext standby is told the active requires TLS, and gets
    // nothing.
    let before = log.count(replication::messages::REQUIRES_TLS);
    let ndir = TempDir::new("plain");
    let plain = open(&ndir, true);
    let fol = start_follower(&plain, port, &ndir, None);
    // Refused by the active, and reported to the standby.
    log.wait_for(replication::messages::REQUIRES_TLS, before + 2)
        .await;
    fol.stop().await;
    assert_eq!(plain.replication_state().expect("state").follow, None);
    srv.stop().await;

    // A TLS standby never talks to a plaintext active.
    let (srv, port) = start_server(&active, None);
    let before = log.count(replication::messages::TLS_NOT_CONFIGURED);
    let tdir = TempDir::new("tls-to-plain");
    let tls_standby = open(&tdir, true);
    let ca = tls::client_config(Trust::Ca(good.ca.clone()), "127.0.0.1").expect("client tls");
    let fol = start_follower(&tls_standby, port, &tdir, Some(ca));
    log.wait_for(replication::messages::TLS_NOT_CONFIGURED, before + 1)
        .await;
    fol.stop().await;
    assert_eq!(tls_standby.replication_state().expect("state").follow, None);
    srv.stop().await;
}

/// Before the handshake, a peer cannot make the active buffer a large
/// frame: anything over the handshake limit is refused at the length.
#[tokio::test]
async fn unauthenticated_large_frame_is_refused() {
    let adir = TempDir::new("prelimit");
    let active = open(&adir, false);
    active.enable_replication_log().expect("enable");
    let (srv, port) = start_server(&active, None);
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let len = u32::try_from(replication::protocol::MAX_FRAME).expect("fits");
    s.write_all(&len.to_be_bytes()).await.expect("write");
    s.write_all(&[1]).await.expect("write");
    // The active closes the connection without waiting for the payload.
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .expect("closed in time")
        .unwrap_or(0);
    assert_eq!(n, 0);
    srv.stop().await;
}
