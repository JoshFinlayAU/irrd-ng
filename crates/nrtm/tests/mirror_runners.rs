//! The mirror runners against a real store: v4's
//! `test_mirror_runners_import.py` and `nrtm4/tests/test_nrtm4_client.py`,
//! asserting what they assert, with local files and a local NRTM server
//! standing in for v4's mocks.

use std::io::Write as _;
use std::sync::{Arc, Mutex, OnceLock};

use nrtm::mirror::pyerr::PyErr;
use nrtm::mirror::runner::{self, MirrorContext};
use nrtm::mirror::settings::{MirrorSettings, SourceMirrorSettings};
use store::{DatabaseStatus, Store, StoreOptions, StoreSettings, Timestamp, Uuid};

// v4's irrd/mirroring/nrtm4/tests/__init__.py keys.
const PRIVATE: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGQrdALKHTVC4sVav\nmKUjXaPB22CWZP3t5XSkLqKHMO2hRANCAAQ9U/aaZwLV4koey4Jvu9cRaxiXna9k\naQ3YwrPzZlwd5MQSZ59kfT2+LAbQmXbZg0NGzptqHoOK0YD3YVBjv4kc\n-----END PRIVATE KEY-----\n";
const PUBLIC: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPVP2mmcC1eJKHsuCb7vXEWsYl52v\nZGkN2MKz82ZcHeTEEmefZH09viwG0Jl22YNDRs6bah6DitGA92FQY7+JHA==\n-----END PUBLIC KEY-----\n";
const PUBLIC_OTHER: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENfIUi9aN8p6dZC7H14GQbZVkmMCr\n3C09qkY+0HiT8RwOl91zJO3g+sW3XsjRZy14isDTxTD3MESwuqCzfNRb2w==\n-----END PUBLIC KEY-----\n";
const SESSION: &str = "ca128382-78d9-41d1-8927-1ecef15275be";

// ---- logging capture (nextest runs each test in its own process) ----

fn logs() -> &'static Mutex<Vec<u8>> {
    static LOGS: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
    LOGS.get_or_init(|| {
        struct W;
        impl std::io::Write for W {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                if let Ok(mut l) = logs().lock() {
                    l.extend_from_slice(b);
                }
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(|| W)
            .try_init();
        Mutex::new(Vec::new())
    })
}

fn log_text() -> String {
    logs()
        .lock()
        .map(|l| String::from_utf8_lossy(&l).into_owned())
        .unwrap_or_default()
}

// ---- helpers ----

struct Env {
    _dir: tempfile::TempDir,
    files: std::path::PathBuf,
    store: Store,
}

fn env() -> Env {
    let _ = logs();
    let dir = tempfile::tempdir().expect("dir");
    let files = dir.path().join("files");
    std::fs::create_dir(&files).expect("files");
    let store = Store::open(
        &StoreOptions::new(dir.path().join("store")),
        StoreSettings::default(),
    )
    .expect("store");
    Env {
        _dir: dir,
        files,
        store,
    }
}

fn ctx(e: &Env, sources: Vec<SourceMirrorSettings>) -> MirrorContext {
    MirrorContext {
        store: e.store.clone(),
        settings: Arc::new(MirrorSettings {
            download_timeout: 5,
            sources,
            ..Default::default()
        }),
    }
}

fn status(e: &Env, source: &str) -> Option<DatabaseStatus> {
    e.store
        .read()
        .expect("read")
        .view()
        .database_status(source)
        .expect("status")
}

fn objects(e: &Env, source: &str) -> Vec<String> {
    let r = e.store.read().expect("read");
    let v = r.view();
    let mut out: Vec<String> = v
        .objects(Some(source), None)
        .expect("objects")
        .map(|o| {
            let (_, o) = o.expect("object");
            format!("{}/{}", o.object_class, o.rpsl_pk)
        })
        .collect();
    out.sort();
    out
}

fn put_status(e: &Env, f: impl FnOnce(&mut DatabaseStatus)) {
    let mut st = DatabaseStatus::new("TEST", Timestamp::now());
    f(&mut st);
    e.store
        .write(move |tx| tx.put_database_status(&st))
        .expect("status");
}

fn sha256_hex(path: &std::path::Path) -> String {
    nrtm::mirror::retrieval::hex(&nrtm::mirror::retrieval::file_hash_sha256(path).expect("hash"))
}

// ---- NRTMv4 ----

fn b64(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = c.iter().fold(0u32, |a, x| (a << 8) | u32::from(*x)) << (8 * (3 - c.len()));
        for i in 0..=c.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn sign(payload: &[u8]) -> String {
    use p256::ecdsa::signature::Signer as _;
    let sk =
        <p256::SecretKey as p256::pkcs8::DecodePrivateKey>::from_pkcs8_pem(PRIVATE).expect("key");
    let signing = p256::ecdsa::SigningKey::from(sk);
    let input = format!("{}.{}", b64(br#"{"alg":"ES256"}"#), b64(payload));
    let sig: p256::ecdsa::Signature = signing.sign(input.as_bytes());
    format!("{input}.{}", b64(&sig.to_bytes()))
}

fn jsonseq(items: &[serde_json::Value]) -> Vec<u8> {
    let mut out = Vec::new();
    for i in items {
        out.push(0x1e);
        out.extend_from_slice(i.to_string().as_bytes());
        out.push(b'\n');
    }
    out
}

/// v4's MOCK_UNF / MOCK_SNAPSHOT / MOCK_DELTA3 / MOCK_DELTA4, as files.
struct Repo {
    unf_url: String,
    hashes: serde_json::Value,
}

fn write_repo(
    e: &Env,
    snapshot: &[serde_json::Value],
    delta3: &[serde_json::Value],
    delta4: &[serde_json::Value],
) -> Repo {
    let w = |name: &str, data: &[u8]| {
        let p = e.files.join(name);
        std::fs::write(&p, data).expect("write");
        sha256_hex(&p)
    };
    let hs = w("snapshot.2.json", &jsonseq(snapshot));
    let h3 = w("delta.3.json", &jsonseq(delta3));
    let h4 = w("delta.4.json", &jsonseq(delta4));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let unf = serde_json::json!({
        "nrtm_version": 4, "timestamp": now, "type": "notification",
        "next_signing_key": PUBLIC_OTHER, "source": "TEST", "session_id": SESSION,
        "version": 4,
        "snapshot": {"version": 3, "url": "snapshot.2.json", "hash": hs},
        "deltas": [
            {"version": 3, "url": "delta.3.json", "hash": h3},
            {"version": 4, "url": "delta.4.json", "hash": h4},
        ],
    });
    let unf_path = e.files.join("update-notification-file.jose");
    std::fs::write(&unf_path, sign(unf.to_string().as_bytes())).expect("unf");
    Repo {
        unf_url: format!("file://{}", unf_path.display()),
        hashes: serde_json::json!({
            "snapshot-3": ["snapshot.2.json", hs],
            "delta-3": ["delta.3.json", h3],
            "delta-4": ["delta.4.json", h4],
        }),
    }
}

fn header(kind: &str, version: i64) -> serde_json::Value {
    serde_json::json!({"nrtm_version": 4, "type": kind, "source": "TEST", "session_id": SESSION, "version": version})
}

fn route() -> serde_json::Value {
    serde_json::json!({"object": "route: 192.0.2.0/24\norigin: AS65530\nsource: TEST"})
}

fn default_repo(e: &Env) -> Repo {
    write_repo(
        e,
        &[header("snapshot", 3), route()],
        &[
            header("delta", 3),
            serde_json::json!({"action": "add_modify", "object": "route: 192.0.2.0/24\norigin: AS65530\nsource: TEST"}),
        ],
        &[
            header("delta", 4),
            serde_json::json!({"action": "delete", "object_class": "route", "primary_key": "192.0.2.0/24AS65530"}),
        ],
    )
}

fn nrtm4_source(url: &str, key: &str) -> SourceMirrorSettings {
    SourceMirrorSettings {
        name: "TEST".into(),
        nrtm4_client_notification_file_url: Some(url.to_owned()),
        nrtm4_client_initial_public_key: Some(key.to_owned()),
        import_timer: 0,
        ..Default::default()
    }
}

fn sid() -> Uuid {
    Uuid::parse_str(SESSION).expect("uuid")
}

#[tokio::test]
async fn nrtm4_valid_from_snapshot_then_deltas() {
    let e = env();
    let repo = default_repo(&e);
    let c = ctx(&e, vec![nrtm4_source(&repo.unf_url, PUBLIC)]);
    assert_eq!(runner::run(&c, "TEST").await, Ok(true));
    let l = log_text();
    assert!(l.contains("No previous known session ID or version, reloading from snapshot"));
    assert!(l.contains("TEST: import of snapshot at version 3"));
    // #1087: deltas wait for the next run.
    assert!(l.contains("Loaded snapshot at version 3, deferring deltas to next run"));
    assert!(!l.contains("Updating from deltas"));
    assert_eq!(objects(&e, "TEST"), ["route/192.0.2.0/24AS65530"]);
    let st = status(&e, "TEST").expect("status");
    assert_eq!(st.nrtm4_client_session_id, Some(sid()));
    assert_eq!(st.nrtm4_client_version, Some(3));
    assert_eq!(st.nrtm4_client_current_key.as_deref(), Some(PUBLIC));
    assert_eq!(st.nrtm4_client_next_key.as_deref(), Some(PUBLIC_OTHER));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            st.nrtm4_client_previous_file_hashes
                .as_ref()
                .expect("hashes")
                .as_str()
        )
        .expect("json"),
        repo.hashes
    );
    // The next run applies delta 4, which deletes the route.
    assert_eq!(runner::run(&c, "TEST").await, Ok(false));
    assert!(log_text().contains("Updating from deltas, starting from version 4"));
    assert!(objects(&e, "TEST").is_empty());
    assert_eq!(
        status(&e, "TEST").expect("status").nrtm4_client_version,
        Some(4)
    );
    // And then it is up to date.
    assert_eq!(runner::run(&c, "TEST").await, Ok(false));
    assert!(log_text().contains("TEST: Up to date at version 4"));
}

#[tokio::test]
async fn nrtm4_valid_from_delta() {
    let e = env();
    let repo = default_repo(&e);
    put_status(&e, |s| {
        s.nrtm4_client_session_id = Some(sid());
        s.nrtm4_client_version = Some(2);
        // Previous hashes that match.
        s.nrtm4_client_previous_file_hashes = Some(store::Json::from_value(
            &serde_json::json!({"delta-3": repo.hashes["delta-3"].clone()}),
        ));
    });
    let c = ctx(&e, vec![nrtm4_source(&repo.unf_url, PUBLIC)]);
    assert_eq!(runner::run(&c, "TEST").await, Ok(false));
    assert!(log_text().contains("Updating from deltas, starting from version 3"));
    assert!(objects(&e, "TEST").is_empty());
    assert_eq!(
        status(&e, "TEST").expect("status").nrtm4_client_version,
        Some(4)
    );
}

async fn nrtm4_error(e: &Env, src: SourceMirrorSettings) -> String {
    match runner::run(&ctx(e, vec![src]), "TEST").await {
        Err(PyErr::Nrtm4(m)) => m,
        other => panic!("expected an NRTM4ClientError, got {other:?}"),
    }
}

#[tokio::test]
async fn nrtm4_invalid_signature() {
    let e = env();
    let repo = default_repo(&e);
    let m = nrtm4_error(&e, nrtm4_source(&repo.unf_url, PUBLIC_OTHER)).await;
    assert!(m.contains("any known keys"), "{m}");
    assert_eq!(
        m,
        format!(
            "TEST: No valid signature found for any known keys; attempting '{}' resulted in error: 'bad_signature: '",
            PUBLIC_OTHER.replace('\n', "\\n")
        )
    );
    assert!(status(&e, "TEST").is_none(), "nothing written");
}

#[tokio::test]
async fn nrtm4_invalid_empty_delta() {
    let e = env();
    let repo = write_repo(
        &e,
        &[header("snapshot", 3), route()],
        &[header("delta", 3)],
        &[header("delta", 4)],
    );
    put_status(&e, |s| {
        s.nrtm4_client_session_id = Some(sid());
        s.nrtm4_client_version = Some(2);
    });
    let m = nrtm4_error(&e, nrtm4_source(&repo.unf_url, PUBLIC)).await;
    assert_eq!(
        m,
        format!("Delta file TEST/{SESSION}/3 did not contain any entries.")
    );
}

#[tokio::test]
async fn nrtm4_invalid_delta_key_error() {
    let e = env();
    let repo = write_repo(
        &e,
        &[header("snapshot", 3), route()],
        &[header("delta", 3), serde_json::json!({})],
        &[header("delta", 4)],
    );
    put_status(&e, |s| {
        s.nrtm4_client_session_id = Some(sid());
        s.nrtm4_client_version = Some(2);
    });
    let m = nrtm4_error(&e, nrtm4_source(&repo.unf_url, PUBLIC)).await;
    assert_eq!(
        m,
        format!("Delta file TEST/{SESSION}/3 contained invalid entry: 'action': {{}}")
    );
}

#[tokio::test]
async fn nrtm4_unf_version_too_low() {
    let e = env();
    let repo = default_repo(&e);
    put_status(&e, |s| {
        s.nrtm4_client_session_id = Some(sid());
        s.nrtm4_client_version = Some(6);
    });
    let m = nrtm4_error(&e, nrtm4_source(&repo.unf_url, PUBLIC)).await;
    assert!(
        m.contains("but version 4 is older than local version 6"),
        "{m}"
    );
}

#[tokio::test]
async fn nrtm4_session_id_mismatch_reloads() {
    let e = env();
    let repo = default_repo(&e);
    put_status(&e, |s| {
        s.nrtm4_client_session_id = Some(Uuid::new_v4());
        s.nrtm4_client_version = Some(2);
    });
    let c = ctx(&e, vec![nrtm4_source(&repo.unf_url, PUBLIC)]);
    assert_eq!(runner::run(&c, "TEST").await, Ok(true));
    let l = log_text();
    assert!(l.contains("Session ID has changed"));
    assert!(l.contains("import of snapshot at version 3"));
    assert_eq!(objects(&e, "TEST"), ["route/192.0.2.0/24AS65530"]);
}

#[tokio::test]
async fn nrtm4_delta_gap_reloads() {
    let e = env();
    let repo = default_repo(&e);
    put_status(&e, |s| {
        s.nrtm4_client_session_id = Some(sid());
        s.nrtm4_client_version = Some(1);
    });
    let c = ctx(&e, vec![nrtm4_source(&repo.unf_url, PUBLIC)]);
    assert_eq!(runner::run(&c, "TEST").await, Ok(true));
    assert!(log_text().contains(
        "Deltas from current version 1 not available on server, reloading from snapshot"
    ));
}

#[tokio::test]
async fn nrtm4_force_reload() {
    let e = env();
    let repo = default_repo(&e);
    put_status(&e, |s| {
        s.force_reload = true;
        s.nrtm4_client_session_id = Some(sid());
        s.nrtm4_client_version = Some(2);
    });
    let c = ctx(&e, vec![nrtm4_source(&repo.unf_url, PUBLIC)]);
    assert_eq!(runner::run(&c, "TEST").await, Ok(true));
    assert!(log_text().contains("Forced reload flag set, reloading from snapshot"));
    let st = status(&e, "TEST").expect("status");
    assert!(!st.force_reload);
    assert_eq!(st.nrtm4_client_version, Some(3));
}

#[tokio::test]
async fn nrtm4_source_mismatch() {
    let e = env();
    let repo = default_repo(&e);
    let mut src = nrtm4_source(&repo.unf_url, PUBLIC);
    src.name = "DIFFERENT-SOURCE".into();
    match runner::run(&ctx(&e, vec![src]), "DIFFERENT-SOURCE").await {
        Err(PyErr::Nrtm4(m)) => assert_eq!(
            m,
            "Value error, Mismatch in source field: expected DIFFERENT-SOURCE, found TEST"
        ),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn nrtm4_history_rewrite() {
    let e = env();
    let repo = default_repo(&e);
    for previous in [
        serde_json::json!({"delta-3": ["delta.3.json", "incorrect-hash"]}),
        serde_json::json!({"delta-3": ["changed filename", repo.hashes["delta-3"][1].clone()]}),
    ] {
        put_status(&e, |s| {
            s.nrtm4_client_session_id = Some(sid());
            s.nrtm4_client_version = Some(4);
            s.nrtm4_client_current_key = Some(PUBLIC.into());
            s.nrtm4_client_previous_file_hashes = Some(store::Json::from_value(&previous));
        });
        let m = nrtm4_error(&e, nrtm4_source(&repo.unf_url, PUBLIC)).await;
        assert!(m.contains("rewriting history"), "{m}");
    }
}

// DIV-003: hashes stored under an earlier session are not compared, so a
// server session reset that reuses "snapshot-N" and "delta-N" references
// reloads from the new snapshot instead of failing on every run as v4 does.
#[tokio::test]
async fn nrtm4_session_reset_ignores_old_session_hashes() {
    let e = env();
    let repo = default_repo(&e);
    let previous = serde_json::json!({
        "snapshot-3": ["old-session-snapshot.json", "old-hash"],
        "delta-3": ["delta.3.json", "incorrect-hash"],
    });
    put_status(&e, |s| {
        s.nrtm4_client_session_id = Some(Uuid::new_v4());
        s.nrtm4_client_version = Some(4);
        s.nrtm4_client_current_key = Some(PUBLIC.into());
        s.nrtm4_client_previous_file_hashes = Some(store::Json::from_value(&previous));
    });
    let c = ctx(&e, vec![nrtm4_source(&repo.unf_url, PUBLIC)]);
    assert_eq!(runner::run(&c, "TEST").await, Ok(true));
    let l = log_text();
    assert!(l.contains("Session ID has changed"), "{l}");
    assert!(!l.contains("rewriting history"), "{l}");
    let st = status(&e, "TEST").expect("status");
    assert_eq!(st.nrtm4_client_session_id, Some(sid()));
    assert_eq!(st.nrtm4_client_version, Some(3));
    let hashes: serde_json::Value = serde_json::from_str(
        st.nrtm4_client_previous_file_hashes
            .as_ref()
            .expect("hashes")
            .as_str(),
    )
    .expect("json");
    assert_eq!(hashes, repo.hashes);
}

#[tokio::test]
async fn nrtm4_known_key_wins_over_config_key() {
    let e = env();
    let repo = default_repo(&e);
    // The configured key verifies, but the stored keys do not.
    put_status(&e, |s| {
        s.nrtm4_client_session_id = Some(sid());
        s.nrtm4_client_version = Some(4);
        s.nrtm4_client_current_key = Some(PUBLIC_OTHER.into());
        s.nrtm4_client_next_key = Some(PUBLIC_OTHER.into());
    });
    let m = nrtm4_error(&e, nrtm4_source(&repo.unf_url, PUBLIC)).await;
    assert!(m.contains("is valid for"), "{m}");
    // A stored key that verifies is used, whatever the configuration says.
    put_status(&e, |s| {
        s.nrtm4_client_session_id = Some(sid());
        s.nrtm4_client_version = Some(4);
        s.nrtm4_client_current_key = Some(PUBLIC.into());
    });
    let c = ctx(&e, vec![nrtm4_source(&repo.unf_url, PUBLIC_OTHER)]);
    assert_eq!(runner::run(&c, "TEST").await, Ok(false));
}

#[tokio::test]
async fn nrtm4_key_rotation() {
    let e = env();
    let repo = default_repo(&e);
    put_status(&e, |s| {
        s.nrtm4_client_session_id = Some(sid());
        s.nrtm4_client_version = Some(4);
        s.nrtm4_client_current_key = Some(PUBLIC_OTHER.into());
        s.nrtm4_client_next_key = Some(PUBLIC.into());
    });
    let c = ctx(&e, vec![nrtm4_source(&repo.unf_url, PUBLIC)]);
    assert_eq!(runner::run(&c, "TEST").await, Ok(false));
    assert!(log_text().contains("key rotated"));
    let st = status(&e, "TEST").expect("status");
    assert_eq!(st.nrtm4_client_current_key.as_deref(), Some(PUBLIC));
    assert_eq!(st.nrtm4_client_next_key.as_deref(), Some(PUBLIC_OTHER));
}

#[tokio::test]
async fn nrtm4_runner_logs_client_errors() {
    let e = env();
    let repo = default_repo(&e);
    runner::run_mirror_update(
        ctx(&e, vec![nrtm4_source(&repo.unf_url, PUBLIC_OTHER)]),
        "TEST".into(),
    )
    .await;
    assert!(log_text().contains("Validation errors occurred while attempting a NRTMv4"));
}

// ---- full imports ----

// gzipped data, contains 'source1' (v4's test data), here a real object.
fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).expect("gz");
    e.finish().expect("gz")
}

fn full_source(e: &Env, serial: Option<&str>) -> SourceMirrorSettings {
    let f1 = e.files.join("source1.rpsl.gz");
    std::fs::write(
        &f1,
        gz(b"mntner: TEST-MNT\nsource: TEST\n\nroute: 192.0.2.0/24\norigin: AS65530\nsource: TEST\n"),
    )
    .expect("w");
    let f2 = e.files.join("source2.rpsl");
    std::fs::write(&f2, b"person: P\nnic-hdl: P1-TEST\nsource: TEST\n\nperson: bad\nnic-hdl: B1-TEST\nsource: OTHER\n").expect("w");
    let urls = vec![
        format!("file://{}", f1.display()),
        format!("file://{}", f2.display()),
    ];
    let serial_url = serial.map(|s| {
        let p = e.files.join("serial");
        std::fs::write(&p, s).expect("w");
        format!("file://{}", p.display())
    });
    SourceMirrorSettings {
        name: "TEST".into(),
        import_source_repr: format!("{urls:?}"),
        import_source: Some(urls),
        import_serial_source_str: serial_url.clone().unwrap_or_else(|| "None".into()),
        import_serial_source: serial_url,
        ..Default::default()
    }
}

#[tokio::test]
async fn full_import_local_files() {
    let e = env();
    let src = full_source(&e, Some("424242\n"));
    let c = ctx(&e, vec![src]);
    assert_eq!(runner::run(&c, "TEST").await, Ok(true));
    assert_eq!(
        objects(&e, "TEST"),
        [
            "mntner/TEST-MNT",
            "person/P1-TEST",
            "route/192.0.2.0/24AS65530"
        ]
    );
    let st = status(&e, "TEST").expect("status");
    assert_eq!(st.serial_newest_mirror, Some(424242));
    assert_eq!(
        st.last_error.as_deref(),
        Some("Invalid source OTHER for object B1-TEST, expected TEST")
    );
    let l = log_text();
    assert!(l.contains("File import for TEST: 2 objects read, 2 objects inserted"));
    assert!(l.contains(
        "File import for TEST: 2 objects read, 1 objects inserted, ignored 1 due to errors"
    ));
}

#[tokio::test]
async fn full_import_cancelled_when_serial_not_newer() {
    let e = env();
    put_status(&e, |s| s.serial_newest_mirror = Some(424243));
    let c = ctx(&e, vec![full_source(&e, Some("424242"))]);
    // nrtm_host unset, so a full reload is attempted, then cancelled.
    assert_eq!(runner::run(&c, "TEST").await, Ok(true));
    assert!(log_text().contains(
        "Current newest serial seen from mirror for TEST is 424243, import_serial is 424242, cancelling import."
    ));
    assert!(objects(&e, "TEST").is_empty());
}

#[tokio::test]
async fn full_import_force_reload_with_old_serial() {
    let e = env();
    put_status(&e, |s| {
        s.serial_newest_mirror = Some(424243);
        s.force_reload = true;
    });
    let c = ctx(&e, vec![full_source(&e, Some("424242"))]);
    assert_eq!(runner::run(&c, "TEST").await, Ok(true));
    assert_eq!(objects(&e, "TEST").len(), 3);
    let st = status(&e, "TEST").expect("status");
    assert!(!st.force_reload);
    assert_eq!(st.serial_newest_mirror, Some(424242));
}

#[tokio::test]
async fn full_import_without_serial() {
    let e = env();
    let c = ctx(&e, vec![full_source(&e, None)]);
    assert_eq!(runner::run(&c, "TEST").await, Ok(true));
    assert_eq!(objects(&e, "TEST").len(), 3);
    assert_eq!(
        status(&e, "TEST").expect("status").serial_newest_mirror,
        None
    );
}

#[tokio::test]
async fn full_import_missing_import_source() {
    let e = env();
    let src = SourceMirrorSettings {
        name: "TEST".into(),
        import_serial_source: Some("ftp://host/serial".into()),
        ..Default::default()
    };
    let c = ctx(&e, vec![src]);
    assert_eq!(runner::run(&c, "TEST").await, Ok(true));
    assert!(log_text().contains("Skipping full RPSL import for TEST, import_source not set."));
    assert!(status(&e, "TEST").is_none());
}

#[tokio::test]
async fn full_import_failures_change_nothing() {
    let e = env();
    let mut src = full_source(&e, Some("424242"));
    src.import_source = Some(vec!["file:///nonexistent/irrd-ng/x.gz".into()]);
    let c = ctx(&e, vec![src.clone()]);
    assert_eq!(
        runner::run(&c, "TEST").await,
        Err(PyErr::Os(
            "[Errno 2] No such file or directory: '/nonexistent/irrd-ng/x.gz'".into()
        ))
    );
    runner::run_mirror_update(c, "TEST".into()).await;
    assert!(log_text().contains(
        "An error occurred while attempting a mirror update or initial import for TEST: [Errno 2] No such file or directory"
    ));
    src.import_source = Some(vec!["gopher://host/x".into()]);
    let c = ctx(&e, vec![src]);
    runner::run_mirror_update(c, "TEST".into()).await;
    assert!(log_text().contains(
        "An exception occurred while attempting a mirror update or initial import for TEST: Invalid URL: gopher://host/x - scheme gopher is not supported"
    ));
    assert!(status(&e, "TEST").is_none());
}

#[tokio::test]
async fn full_import_over_http() {
    let e = env();
    let body = gz(b"mntner: TEST-MNT\nsource: TEST\n");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                assert!(req.contains("user-agent: irrd/4.5.4"), "{req}");
                let (status, data): (&str, Vec<u8>) = if req.starts_with("GET /db.gz ") {
                    ("200 OK", body)
                } else if req.starts_with("GET /serial ") {
                    ("200 OK", b"77\n".to_vec())
                } else {
                    ("404 Not Found", b"nope".to_vec())
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    data.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&data).await;
            });
        }
    });
    let src = SourceMirrorSettings {
        name: "TEST".into(),
        import_source: Some(vec![format!("http://127.0.0.1:{port}/db.gz")]),
        import_serial_source: Some(format!("http://127.0.0.1:{port}/serial")),
        ..Default::default()
    };
    let c = ctx(&e, vec![src.clone()]);
    assert_eq!(runner::run(&c, "TEST").await, Ok(true));
    assert_eq!(objects(&e, "TEST"), ["mntner/TEST-MNT"]);
    assert_eq!(
        status(&e, "TEST").expect("status").serial_newest_mirror,
        Some(77)
    );
    let mut bad = src;
    bad.import_source = Some(vec![format!("http://127.0.0.1:{port}/missing")]);
    bad.import_serial_source = None;
    assert_eq!(
        runner::run(&ctx(&e, vec![bad]), "TEST").await,
        Err(PyErr::Os(format!(
            "Failed to download http://127.0.0.1:{port}/missing: 404: b'nope'"
        )))
    );
}

// ---- NRTMv3 ----

async fn nrtm_server(response: &'static str) -> (u16, Arc<Mutex<Vec<String>>>) {
    nrtm_server_holding(response, false).await
}

/// A server that answers every query with `response`, then closes, or
/// with `hold`, keeps the connection open for a while.
async fn nrtm_server_holding(response: &'static str, hold: bool) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let queries = Arc::new(Mutex::new(Vec::new()));
    let q2 = queries.clone();
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        while let Ok((s, _)) = listener.accept().await {
            let (r, mut w) = s.into_split();
            let mut line = String::new();
            let _ = tokio::io::BufReader::new(r).read_line(&mut line).await;
            if let Ok(mut q) = q2.lock() {
                q.push(line);
            }
            let _ = w.write_all(response.as_bytes()).await;
            if hold {
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    drop(w);
                });
            }
        }
    });
    (port, queries)
}

const NRTM_RESPONSE: &str = "%START Version: 3 TEST 424243-424245\n\nADD 424243\n\nmntner: TEST-MNT\nsource: TEST\n\nADD 424244\n\nroute: 192.0.2.0/24\norigin: AS65530\nsource: TEST\n\nDEL 424245\n\nmntner: TEST-MNT\nsource: TEST\n\n%END TEST\n";

#[tokio::test]
async fn nrtm3_update_stream() {
    let e = env();
    put_status(&e, |s| s.serial_newest_mirror = Some(424242));
    let (port, queries) = nrtm_server(NRTM_RESPONSE).await;
    let src = SourceMirrorSettings {
        name: "TEST".into(),
        nrtm_host: Some("127.0.0.1".into()),
        nrtm_port: Ok(i64::from(port)),
        nrtm3_client_timeout: Ok(10),
        ..Default::default()
    };
    let c = ctx(&e, vec![src]);
    assert_eq!(runner::run(&c, "TEST").await, Ok(false));
    assert_eq!(
        queries.lock().expect("q").as_slice(),
        ["-g TEST:3:424243-LAST\n"]
    );
    assert_eq!(objects(&e, "TEST"), ["route/192.0.2.0/24AS65530"]);
    assert_eq!(
        status(&e, "TEST").expect("status").serial_newest_mirror,
        Some(424245)
    );
    let l = log_text();
    assert!(l.contains("Retrieving NRTM updates for TEST from serial 424243 on 127.0.0.1:"));
    assert!(l.contains("Completed NRTM operation TEST/424244/ADD/route/192.0.2.0/24AS65530"));
    assert!(l.contains("Completed NRTM operation TEST/424245/DEL/mntner/TEST-MNT"));
}

#[tokio::test]
async fn nrtm3_stream_errors_change_nothing() {
    let e = env();
    put_status(&e, |s| s.serial_newest_mirror = Some(424242));
    let (port, _) = nrtm_server_holding(
        "%START Version: 3 TEST 424243-424245\n\nADD 424243\n\nmntner: TEST-MNT\nsource: TEST\n",
        true,
    )
    .await;
    let src = SourceMirrorSettings {
        name: "TEST".into(),
        nrtm_host: Some("127.0.0.1".into()),
        nrtm_port: Ok(i64::from(port)),
        nrtm3_client_timeout: Ok(1),
        ..Default::default()
    };
    runner::run_mirror_update(ctx(&e, vec![src]), "TEST".into()).await;
    let l = log_text();
    assert!(l.contains("Whois query -g TEST:3:424243-LAST timed out on 127.0.0.1"));
    assert!(l.contains("An exception occurred while attempting a mirror update or initial import for TEST: NRTM stream error for TEST: last comment paragraph expected to be"));
    assert!(objects(&e, "TEST").is_empty());
    let st = status(&e, "TEST").expect("status");
    assert_eq!(st.serial_newest_mirror, Some(424242));
    assert_eq!(st.last_error, None);
}

#[tokio::test]
async fn nrtm3_connection_refused() {
    let e = env();
    put_status(&e, |s| s.serial_newest_mirror = Some(1));
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    drop(l);
    let src = SourceMirrorSettings {
        name: "TEST".into(),
        nrtm_host: Some("127.0.0.1".into()),
        nrtm_port: Ok(i64::from(port)),
        ..Default::default()
    };
    assert_eq!(
        runner::run(&ctx(&e, vec![src]), "TEST").await,
        Err(PyErr::Os("[Errno 111] Connection refused".into()))
    );
}
