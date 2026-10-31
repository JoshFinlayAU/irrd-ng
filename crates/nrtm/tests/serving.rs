//! Serving data: exports and the NRTMv4 server against a real store,
//! with irrd-ng's own NRTMv4 client reading the files back.
//!
//! Byte-level parity with v4 for both is checked by the mirroring
//! differential (`parity/mirror/run.sh`); these tests pin the behaviour of
//! `test_mirror_runners_export.py` and `nrtm4/tests/test_nrtm4_server.py`.

use std::io::Read as _;

use nrtm::file_import::{self, ImportSettings, ParseEnv};
use nrtm::mirror::runner::{self, MirrorContext};
use nrtm::mirror::settings::{MirrorSettings, SourceMirrorSettings};
use nrtm::serve::{export, nrtm4_server};
use rpki::{ScopeFilterConfig, ScopeFilterValidator};
use rpsl::{Keyring, RpslSettings};
use store::{SourceSettings, Store, StoreOptions, StoreSettings, Timestamp};

const PRIVATE: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGQrdALKHTVC4sVav\nmKUjXaPB22CWZP3t5XSkLqKHMO2hRANCAAQ9U/aaZwLV4koey4Jvu9cRaxiXna9k\naQ3YwrPzZlwd5MQSZ59kfT2+LAbQmXbZg0NGzptqHoOK0YD3YVBjv4kc\n-----END PRIVATE KEY-----\n";
const PUBLIC: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPVP2mmcC1eJKHsuCb7vXEWsYl52v\nZGkN2MKz82ZcHeTEEmefZH09viwG0Jl22YNDRs6bah6DitGA92FQY7+JHA==\n-----END PUBLIC KEY-----\n";
const PRIVATE_OTHER: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmHtbXrQ0uEcrzeZK\niaK8UnpD5c/YAmqdUHqoHLz997ShRANCAAQ18hSL1o3ynp1kLsfXgZBtlWSYwKvc\nLT2qRj7QeJPxHA6X3XMk7eD6xbdeyNFnLXiKwNPFMPcwRLC6oLN81Fvb\n-----END PRIVATE KEY-----\n";
const PUBLIC_OTHER: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENfIUi9aN8p6dZC7H14GQbZVkmMCr\n3C09qkY+0HiT8RwOl91zJO3g+sW3XsjRZy14isDTxTD3MESwuqCzfNRb2w==\n-----END PUBLIC KEY-----\n";

const DATA: &str = "\
route:          192.0.2.0/24
origin:         AS65537
mnt-by:         MNT-A
source:         TEST

aut-num:        AS65537
as-name:        A
mnt-by:         MNT-A
source:         TEST

route6:         2001:db8::/32
origin:         AS65537
mnt-by:         MNT-A
source:         TEST

mntner:         MNT-A
auth:           CRYPT-PW LEuuhsBJNFV0Q
upd-to:         a@example.net
mnt-by:         MNT-A
source:         TEST

route:          10.0.0.0/8
origin:         AS65537
mnt-by:         MNT-A
source:         TEST
";

fn store_at(path: &std::path::Path, journal: bool) -> Store {
    let mut s = StoreSettings::default();
    s.sources.insert(
        "TEST".into(),
        SourceSettings {
            keep_journal: journal,
            ..Default::default()
        },
    );
    let mut o = StoreOptions::new(path);
    o.initial_map_size = 16 << 20;
    Store::open(&o, s).expect("store")
}

/// Make `text` the whole of source TEST, journaling the changes, as
/// `irrd_update_database` does.
fn set_source(st: &Store, text: &str) {
    let rpsl_settings = RpslSettings::default();
    let keyring = Keyring::new();
    let scope = ScopeFilterValidator::new(ScopeFilterConfig::default());
    let env = ParseEnv {
        rpsl: &rpsl_settings,
        keyring: &keyring,
        roa_validator: None,
        scopefilter: &scope,
    };
    let settings = ImportSettings {
        source: "TEST".into(),
        object_class_filter: None,
        strict_import_keycert_objects: false,
        direct_error_return: true,
        keep_plain_text: false,
    };
    let paragraphs = rpsl::split_rpsl_file(text.as_bytes());
    let parsed = file_import::parse_paragraphs(&paragraphs, &settings, &env).expect("parse");
    st.write(move |tx| file_import::apply_update_import(tx, "TEST", &parsed.actions))
        .expect("apply");
}

fn gunzip(path: &std::path::Path) -> (Vec<u8>, String) {
    let raw = std::fs::read(path).expect("read");
    let mut s = String::new();
    flate2::read::GzDecoder::new(&raw[..])
        .read_to_string(&mut s)
        .expect("gunzip");
    (raw, s)
}

fn serving_source(dir: &std::path::Path) -> SourceMirrorSettings {
    SourceMirrorSettings {
        name: "TEST".into(),
        export_destination: Some(format!("{}/filtered/", dir.display())),
        export_destination_unfiltered: Some(format!("{}/unfiltered", dir.display())),
        dummify: rpsl::text::DummifySettings {
            object_classes: vec!["mntner".into()],
            attributes: vec![("upd-to".into(), "unread@example.net".into())],
            remarks: Some("Dummified".into()),
        },
        nrtm4_server_local_path: Some(dir.join("nrtm4").display().to_string()),
        nrtm4_server_private_key: Some(PRIVATE.into()),
        runs_rpsl_export: true,
        runs_nrtm4_server: true,
        ..Default::default()
    }
}

#[test]
fn export_filtered_and_unfiltered() {
    let dir = tempfile::tempdir().expect("dir");
    let st = store_at(&dir.path().join("store"), true);
    set_source(&st, DATA);
    for d in ["filtered", "unfiltered"] {
        std::fs::create_dir(dir.path().join(d)).expect("mkdir");
    }
    let src = serving_source(dir.path());
    export::run_export(&st, &src);

    let (raw, text) = gunzip(&dir.path().join("filtered/test.db.gz"));
    // gzip.open() on the NamedTemporaryFile: its name is in the header.
    assert_eq!(&raw[..4], b"\x1f\x8b\x08\x08");
    assert_eq!(&raw[10..13], b"tmp");
    assert_eq!(&raw[8..10], b"\x02\xff");
    // v4's object order: IPv4 by address, IPv6, then by ASN, then by key.
    let keys: Vec<&str> = text
        .split("\n\n")
        .filter_map(|p| p.lines().next())
        .collect();
    assert_eq!(
        keys,
        [
            "route:          10.0.0.0/8",
            "route:          192.0.2.0/24",
            "route6:         2001:db8::/32",
            "aut-num:        AS65537",
            "mntner:         MNT-A",
            "# EOF",
        ]
    );
    assert!(text.ends_with("remarks:        Dummified\n\n# EOF\n"));
    assert!(text.contains(
        "auth:           CRYPT-PW DummyValue  # Filtered for security\nupd-to:         unread@example.net\nmnt-by:         MNT-A\n"
    ));
    let (_, unfiltered) = gunzip(&dir.path().join("unfiltered/test.db.gz"));
    assert!(unfiltered.contains("CRYPT-PW LEuuhsBJNFV0Q\nupd-to:         a@example.net\n"));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("filtered/TEST.CURRENTSERIAL")).expect("serial"),
        status_of(&st)
            .serial_newest_seen
            .expect("serial")
            .to_string()
    );
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(dir.path().join("filtered/test.db.gz"))
        .expect("meta")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644);
    let txn = st.read().expect("read");
    let status = txn
        .view()
        .database_status("TEST")
        .expect("status")
        .expect("row");
    assert_eq!(status.serial_last_export, status.serial_newest_seen);
}

#[test]
fn export_without_serial_removes_old_serial_file() {
    let dir = tempfile::tempdir().expect("dir");
    let st = store_at(&dir.path().join("store"), false);
    std::fs::create_dir(dir.path().join("filtered")).expect("mkdir");
    std::fs::write(dir.path().join("filtered/TEST.CURRENTSERIAL"), "1").expect("old");
    let src = SourceMirrorSettings {
        export_destination_unfiltered: None,
        ..serving_source(dir.path())
    };
    export::run_export(&st, &src);
    let (_, text) = gunzip(&dir.path().join("filtered/test.db.gz"));
    assert_eq!(text, "# EOF\n");
    assert!(!dir.path().join("filtered/TEST.CURRENTSERIAL").exists());
    // A missing destination is logged, not fatal.
    let src = SourceMirrorSettings {
        export_destination: Some(dir.path().join("missing").display().to_string()),
        ..src
    };
    export::run_export(&st, &src);
}

fn client_ctx(st: &Store, unf: &std::path::Path) -> MirrorContext {
    MirrorContext {
        store: st.clone(),
        settings: std::sync::Arc::new(MirrorSettings {
            sources: vec![SourceMirrorSettings {
                name: "TEST".into(),
                nrtm4_client_notification_file_url: Some(format!("file://{}", unf.display())),
                nrtm4_client_initial_public_key: Some(PUBLIC.into()),
                import_timer: 0,
                ..Default::default()
            }],
            download_timeout: 5,
            ..Default::default()
        }),
    }
}

/// (class, key) of every object, and the mntner's text.
fn contents(st: &Store) -> (Vec<String>, String) {
    let txn = st.read().expect("read");
    let view = txn.view();
    let mut keys = Vec::new();
    let mut mntner = String::new();
    for o in view.objects(Some("TEST"), None).expect("objects") {
        let o = o.expect("object").1;
        keys.push(format!("{}/{}", o.object_class, o.rpsl_pk));
        if o.object_class == "mntner" {
            mntner = o.object_text.to_owned();
        }
    }
    keys.sort();
    (keys, mntner)
}

fn assert_mirrored(up: &Store, down: &Store) {
    let (keys_up, _) = contents(up);
    let (keys_down, mntner) = contents(down);
    assert_eq!(keys_down, keys_up);
    assert!(mntner.contains("CRYPT-PW DummyValue  # Filtered for security\n"));
    assert!(mntner.contains("upd-to:         unread@example.net\n"));
    assert!(mntner.contains("remarks:        Dummified\n"));
}

fn status_of(st: &Store) -> store::DatabaseStatus {
    let txn = st.read().expect("read");
    txn.view()
        .database_status("TEST")
        .expect("status")
        .expect("row")
}

#[tokio::test]
async fn nrtm4_server_round_trip_through_the_client() {
    let dir = tempfile::tempdir().expect("dir");
    let up = store_at(&dir.path().join("up"), true);
    let down = store_at(&dir.path().join("down"), false);
    set_source(&up, DATA);
    let repo = dir.path().join("nrtm4");
    std::fs::create_dir(&repo).expect("mkdir");
    let src = serving_source(dir.path());
    let unf = repo.join(nrtm4_server::UPDATE_NOTIFICATION_FILENAME);

    // First run: a new session with a snapshot at version 1.
    nrtm4_server::run_writer(&up, &src, Timestamp::now()).expect("run 1");
    let st = status_of(&up);
    let session = st.nrtm4_server_session_id.expect("session");
    assert_eq!(st.nrtm4_server_version, Some(1));
    assert_eq!(st.nrtm4_server_last_snapshot_version, Some(1));
    let max_serial = up
        .read()
        .expect("read")
        .view()
        .max_serial_global()
        .expect("max");
    assert_eq!(st.nrtm4_server_last_snapshot_global_serial, max_serial);
    let snapshot = st.nrtm4_server_last_snapshot_filename.expect("snapshot");
    assert!(snapshot.starts_with(&format!("nrtm-snapshot.{session}.1.")));
    let (raw, snap) = gunzip(&repo.join(&snapshot));
    assert_eq!(&raw[10..24], b"nrtm-snapshot.");
    assert!(snap.starts_with(&format!(
        "\x1e{{\"nrtm_version\":4,\"source\":\"TEST\",\"session_id\":\"{session}\",\"version\":1,\"type\":\"snapshot\"}}\n\x1e{{\"object\":\"route:          10.0.0.0\\/8\\n"
    )));

    let c = client_ctx(&down, &unf);
    runner::run(&c, "TEST").await.expect("client 1");
    assert_mirrored(&up, &down);

    // Changes upstream: a delta at version 2, carrying only TEST's entries.
    let changed = DATA.replace("as-name:        A\n", "as-name:        B\n");
    let changed = changed
        .split("\n\n")
        .skip(1)
        .collect::<Vec<_>>()
        .join("\n\n");
    set_source(&up, &changed);
    nrtm4_server::run_writer(&up, &src, Timestamp::now()).expect("run 2");
    let st = status_of(&up);
    assert_eq!(st.nrtm4_server_version, Some(2));
    let deltas = st.nrtm4_server_previous_deltas.expect("deltas").value();
    assert_eq!(deltas[0]["version"], 2);
    let max_serial2 = up
        .read()
        .expect("read")
        .view()
        .max_serial_global()
        .expect("max");
    assert_eq!(
        deltas[0]["serial_global_start"].as_i64(),
        max_serial.map(|m| m + 1)
    );
    assert_eq!(deltas[0]["serial_global_end"].as_i64(), max_serial2);
    let (_, delta) = gunzip(&repo.join(deltas[0]["filename"].as_str().expect("name")));
    assert!(delta.contains("{\"action\":\"delete\",\"object_class\":\"route\",\"primary_key\":\"192.0.2.0\\/24AS65537\"}\n"));
    // Nothing changed: no new delta, same version.
    nrtm4_server::run_writer(&up, &src, Timestamp::now()).expect("run 3");
    assert_eq!(status_of(&up).nrtm4_server_version, Some(2));

    runner::run(&c, "TEST").await.expect("client 2");
    assert_mirrored(&up, &down);
    assert_eq!(status_of(&down).nrtm4_client_version, Some(2));

    // Key rotation: the next key is announced in the UNF.
    let rotating = SourceMirrorSettings {
        nrtm4_server_private_key_next: Some(PRIVATE_OTHER.into()),
        ..src.clone()
    };
    nrtm4_server::run_writer(&up, &rotating, Timestamp::now()).expect("run 4");
    runner::run(&c, "TEST").await.expect("client 3");
    assert_eq!(
        status_of(&down).nrtm4_client_next_key.as_deref(),
        Some(PUBLIC_OTHER)
    );

    // A missing snapshot fails the integrity check: a new session.
    std::fs::remove_file(repo.join(&snapshot)).expect("rm");
    nrtm4_server::run_writer(&up, &src, Timestamp::now()).expect("run 5");
    let st = status_of(&up);
    assert_ne!(st.nrtm4_server_session_id, Some(session));
    assert_eq!(st.nrtm4_server_version, Some(1));
    assert_eq!(
        st.nrtm4_server_previous_deltas.expect("deltas").value(),
        serde_json::json!([])
    );
    // The old session's delta is dangling and goes.
    let left: Vec<String> = std::fs::read_dir(&repo)
        .expect("ls")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("nrtm-delta."))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

#[test]
fn nrtm4_server_expires_deltas_and_snapshots() {
    let dir = tempfile::tempdir().expect("dir");
    let up = store_at(&dir.path().join("up"), true);
    set_source(&up, DATA);
    let repo = dir.path().join("nrtm4");
    std::fs::create_dir(&repo).expect("mkdir");
    let src = SourceMirrorSettings {
        nrtm4_server_snapshot_frequency: 3600,
        ..serving_source(dir.path())
    };
    let t0 = Timestamp::now();
    nrtm4_server::run_writer(&up, &src, t0).expect("run 1");
    let first_snapshot = status_of(&up)
        .nrtm4_server_last_snapshot_filename
        .expect("s");
    set_source(
        &up,
        &DATA.replace("as-name:        A\n", "as-name:        B\n"),
    );
    let hour = 3_600_000_000;
    nrtm4_server::run_writer(&up, &src, Timestamp(t0.0 + hour)).expect("run 2");
    let st = status_of(&up);
    assert_eq!(st.nrtm4_server_version, Some(2));
    // Snapshot older than the frequency and behind the version: renewed.
    nrtm4_server::run_writer(&up, &src, Timestamp(t0.0 + 2 * hour + 1)).expect("run 3");
    let st = status_of(&up);
    assert_eq!(st.nrtm4_server_last_snapshot_version, Some(2));
    // The old snapshot stays until 24 hours after it was written (by file
    // time, so it is still here).
    assert!(repo.join(&first_snapshot).exists());
    // More than 24 hours after it was made, the delta has expired.
    nrtm4_server::run_writer(&up, &src, Timestamp(t0.0 + 25 * hour + 1)).expect("run 4");
    let st = status_of(&up);
    assert_eq!(
        st.nrtm4_server_previous_deltas.expect("deltas").value(),
        serde_json::json!([])
    );
    assert!(!repo.join(&first_snapshot).exists());
    assert_eq!(st.nrtm4_server_version, Some(2));
}
