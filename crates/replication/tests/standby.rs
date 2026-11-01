//! Two stores, an active and a standby, connected over TCP: the standby
//! converges on the active's rows, survives restarts of itself and of the
//! active's server, recovers from a trimmed log and from a resync, refuses
//! a wrong secret, and never writes on its own.

#![allow(clippy::unwrap_used, clippy::expect_used, unreachable_pub)]

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use replication::{FollowerSettings, ServerSettings, SharedKey, follower, server};
use store::{
    IpPrefix, JournalEntryOrigin, Json, NewRpslObject, RoutePreferenceStatus, RpkiStatus,
    ScopeFilterStatus, SettingRow, SourceSettings, Store, StoreOptions, StoreSettings, Timestamp,
};
use tokio::sync::watch;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "irrd-ng-replication-{tag}-{}-{n}",
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

/// Log lines, captured so the test can see which path the stream took.
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
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
    fn count(&self, needle: &str) -> usize {
        self.text().matches(needle).count()
    }
}

const SECRET: &[u8] = b"a shared secret of some length";

fn key(secret: &[u8]) -> SharedKey {
    SharedKey::derive(secret).expect("derive")
}

fn store_settings(standby: bool) -> StoreSettings {
    StoreSettings {
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
    }
}

fn open(dir: &TempDir, standby: bool) -> Store {
    let mut o = StoreOptions::new(dir.0.join("store"));
    o.initial_map_size = 64 << 20;
    Store::open(&o, store_settings(standby)).expect("open store")
}

fn object(pk: &str, class: &str, text: &str) -> NewRpslObject {
    NewRpslObject {
        rpsl_pk: pk.to_owned(),
        source: "TEST".to_owned(),
        object_class: class.to_owned(),
        parsed_data: Json::canonical(r#"{"mnt-by": ["MNT-TEST"], "source": "TEST"}"#)
            .expect("json"),
        object_text: text.to_owned(),
        ip_first: None,
        ip_last: None,
        prefix: None,
        prefix_length: None,
        asn_first: None,
        asn_last: None,
        rpki_status: RpkiStatus::NotFound,
        scopefilter_status: ScopeFilterStatus::InScope,
        route_preference_status: RoutePreferenceStatus::Visible,
    }
}

fn route(prefix: &str, asn: u32) -> NewRpslObject {
    let p = IpPrefix::parse(prefix).expect("prefix");
    let last = std::net::IpAddr::V4(std::net::Ipv4Addr::from(p.last() as u32));
    NewRpslObject {
        prefix: Some(p),
        prefix_length: Some(u32::from(p.len)),
        ip_first: Some(p.addr),
        ip_last: Some(last),
        asn_first: Some(asn),
        asn_last: Some(asn),
        ..object(
            &format!("{prefix}AS{asn}"),
            "route",
            &format!("route: {prefix}\norigin: AS{asn}\n"),
        )
    }
}

fn upsert(store: &Store, objects: Vec<NewRpslObject>) {
    store
        .write(move |tx| {
            for o in &objects {
                tx.upsert_rpsl_object(o, JournalEntryOrigin::AuthChange, None, None)?;
            }
            Ok(())
        })
        .expect("write");
}

/// Every replicated row of a store.
fn rows(store: &Store) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    store
        .replication_snapshot(&mut |_| Ok(()), &mut |t, k, v| {
            out.push((t, k.to_vec(), v.to_vec()));
            Ok(())
        })
        .expect("rows");
    out
}

/// Wait until the standby has applied everything the active logged, then
/// check the two stores hold the same rows.
async fn converge(active: &Store, standby: &Store) {
    let started = Instant::now();
    loop {
        let a = active.replication_state().expect("state");
        let s = standby.replication_state().expect("state");
        if s.follow == Some((a.id.clone().expect("log enabled"), a.last_seq)) {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "standby did not converge: active {a:?}, standby {s:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (a, s) = (rows(active), rows(standby));
    if a != s {
        let count = |r: &[(u8, Vec<u8>, Vec<u8>)], t: u8| r.iter().filter(|x| x.0 == t).count();
        for (i, name) in store::TABLE_NAMES.iter().enumerate() {
            let (ca, cs) = (count(&a, i as u8), count(&s, i as u8));
            if ca != cs {
                eprintln!("{name}: active {ca}, standby {cs}");
            }
        }
    }
    assert_eq!(a.len(), s.len(), "row counts differ");
    assert!(a == s, "rows differ");
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

fn start_server(store: &Store, port: u16) -> (Running, u16) {
    let mut s = ServerSettings::new("127.0.0.1", port, key(SECRET));
    s.heartbeat = Duration::from_millis(200);
    let listener = server::bind(&s).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(server::serve(listener, store.clone(), Arc::new(s), rx));
    (Running { shutdown: tx, task }, port)
}

fn start_follower(store: &Store, port: u16, secret: &[u8], spool: &TempDir) -> Running {
    let mut s = FollowerSettings::new("127.0.0.1", port, key(secret), &spool.0);
    s.idle_timeout = Duration::from_secs(2);
    s.max_backoff = Duration::from_secs(1);
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(follower::run(store.clone(), Arc::new(s), rx));
    Running { shutdown: tx, task }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standby_follows_the_active() {
    let log = Captured::default();
    let writer = log.clone();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .try_init();

    let (adir, sdir) = (TempDir::new("active"), TempDir::new("standby"));
    let active = open(&adir, false);
    active.enable_replication_log().expect("enable");

    // Rows in many tables before the standby ever connects.
    upsert(
        &active,
        vec![
            object("MNT-TEST", "mntner", "mntner: MNT-TEST\n"),
            route("192.0.2.0/24", 65537),
            route("198.51.100.0/24", 65538),
        ],
    );
    active
        .write(|tx| {
            tx.insert_roa_object(
                4,
                IpPrefix::parse("192.0.2.0/24").expect("prefix"),
                65537,
                24,
                "TA",
            )?;
            tx.put_setting(&SettingRow {
                name: "nrtm4_server_key".into(),
                value: Some("v".into()),
                created: Timestamp::now(),
            })?;
            tx.put_pgp_key("0123456789ABCDEF0123456789ABCDEF01234567", b"key")?;
            tx.record_serial_seen("TEST", 1)
        })
        .expect("write");

    // A new standby gets a snapshot.
    let standby = open(&sdir, true);
    let (srv, port) = start_server(&active, 0);
    let fol = start_follower(&standby, port, SECRET, &sdir);
    converge(&active, &standby).await;
    assert_eq!(log.count("streaming a snapshot"), 1);

    // Incremental changes: updates, deletes, concurrent writers whose
    // transactions the writer groups, and a rolled-back transaction, which
    // must leave no trace.
    upsert(&active, vec![route("192.0.2.0/24", 65537)]);
    active
        .write(|tx| {
            tx.delete_rpsl_object(
                "TEST",
                "198.51.100.0/24AS65538",
                "route",
                JournalEntryOrigin::AuthChange,
                None,
                false,
            )
            .map(|_| ())
        })
        .expect("delete");
    let failed = active.write(|tx| {
        tx.upsert_rpsl_object(
            &object("AS-ROLLEDBACK", "as-set", "as-set: AS-ROLLEDBACK\n"),
            JournalEntryOrigin::AuthChange,
            None,
            None,
        )?;
        Err::<(), _>(store::StoreError::Aborted("roll back".into()))
    });
    assert!(failed.is_err());
    let writers: Vec<_> = (0..8)
        .map(|i| {
            let a = active.clone();
            std::thread::spawn(move || {
                upsert(&a, vec![route(&format!("203.0.113.{}/32", i), 65540 + i)])
            })
        })
        .collect();
    for w in writers {
        w.join().expect("writer");
    }
    converge(&active, &standby).await;
    assert!(
        standby
            .read()
            .expect("read")
            .view()
            .object("TEST", "as-set", "AS-ROLLEDBACK")
            .expect("q")
            .is_none()
    );

    // The standby never writes on its own: its own write path is refused,
    // and while the active is idle the standby commits nothing at all,
    // across several heartbeats.
    let refused = standby.write(|tx| {
        tx.upsert_rpsl_object(
            &object("AS-LOCAL", "as-set", "as-set: AS-LOCAL\n"),
            JournalEntryOrigin::AuthChange,
            None,
            None,
        )
    });
    assert!(matches!(refused, Err(store::StoreError::ReadOnly)));
    let txn = standby.last_txn_id();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(standby.last_txn_id(), txn, "the idle standby wrote");

    // A restarted standby carries on from where it was, without a snapshot.
    fol.stop().await;
    drop(standby);
    upsert(
        &active,
        vec![object("AS-WHILE-DOWN", "as-set", "as-set: AS-WHILE-DOWN\n")],
    );
    let standby = open(&sdir, true);
    let fol = start_follower(&standby, port, SECRET, &sdir);
    converge(&active, &standby).await;
    assert_eq!(log.count("streaming a snapshot"), 1);
    assert!(log.count("streaming from log entry") >= 1);

    // The active's server goes away and comes back: the standby
    // reconnects and catches up.
    srv.stop().await;
    upsert(
        &active,
        vec![object(
            "AS-SERVER-DOWN",
            "as-set",
            "as-set: AS-SERVER-DOWN\n",
        )],
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (srv, port2) = start_server(&active, port);
    assert_eq!(port2, port);
    converge(&active, &standby).await;
    assert!(log.count("interrupted") >= 1);

    // A standby that was away longer than the kept log gets a snapshot.
    fol.stop().await;
    for i in 0..5 {
        upsert(
            &active,
            vec![object(&format!("AS-TRIM{i}"), "as-set", "as-set: X\n")],
        );
    }
    let future = Timestamp(Timestamp::now().0 + 1_000_000);
    assert!(active.trim_replication_log(future).expect("trim") >= 5);
    let fol = start_follower(&standby, port, SECRET, &sdir);
    converge(&active, &standby).await;
    assert_eq!(log.count("streaming a snapshot"), 2);

    // A transaction too large to log row by row becomes a resync, which
    // the server turns into a snapshot.
    let big = "x".repeat(1 << 20);
    let bulk: Vec<_> = (0..40)
        .map(|i| object(&format!("AS-BIG{i}"), "as-set", &big))
        .collect();
    upsert(&active, bulk);
    converge(&active, &standby).await;
    assert_eq!(log.count("Loading a snapshot"), 3);
    // And incremental streaming resumes after it.
    upsert(
        &active,
        vec![object("AS-AFTER", "as-set", "as-set: AS-AFTER\n")],
    );
    converge(&active, &standby).await;
    assert_eq!(log.count("Loading a snapshot"), 3);

    // A standby with the wrong secret gets nothing.
    let odir = TempDir::new("other");
    let other = open(&odir, true);
    let bad = start_follower(&other, port, b"not the secret", &odir);
    let started = Instant::now();
    while log.count("authentication failed") < 2 {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "no refusal logged"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(other.replication_state().expect("state").follow, None);
    assert_eq!(
        other
            .read()
            .expect("read")
            .view()
            .object_count()
            .expect("n"),
        0
    );
    bad.stop().await;

    fol.stop().await;
    srv.stop().await;
}
