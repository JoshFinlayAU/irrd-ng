//! NRTMv3 serving (`-g`) over a real store: the expectations of v4's
//! `irrd/mirroring/tests/test_nrtm_generator.py`, run through the whois
//! session so the framing is covered too.

use std::sync::Arc;

use query::{ConfigValue, NrtmServer, QuerySettings, SourceQuerySettings, WhoisSession};
use store::{
    DatabaseOperation, DatabaseStatus, JournalEntry, JournalEntryOrigin, Store, StoreOptions,
    StoreSettings, Timestamp,
};

struct Tmp(std::path::PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const MNT_TEXT: &str = "mntner:         TEST-MNT\ndescr:          description\nnotify:         notify@example.com\nauth:           CRYPT-PW foobar\n";

fn entry(serial: i64, op: DatabaseOperation, text: &str, age_days: i64) -> JournalEntry {
    JournalEntry {
        pk: uuid::Uuid::new_v4(),
        serial_global: serial + 1000,
        rpsl_pk: "TEST-MNT".into(),
        source: "TEST".into(),
        origin: JournalEntryOrigin::AuthChange,
        serial_nrtm: serial,
        operation: op,
        object_class: "mntner".into(),
        object_text: text.into(),
        timestamp: Timestamp(Timestamp::now().0 - age_days * 86_400_000_000),
    }
}

/// A store with v4's test journal: ADD 120 and DEL 180, with
/// `serial_oldest_journal` 100 and `serial_newest_journal` 200.
fn setup(tag: &str, age_days: i64) -> (Tmp, Store) {
    let p = std::env::temp_dir().join(format!("irrd-ng-nrtm3-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    let mut o = StoreOptions::new(&p);
    o.initial_map_size = 16 << 20;
    let st = Store::open(&o, StoreSettings::default()).expect("store");
    st.write(move |tx| {
        tx.put_journal_entry(&entry(
            120,
            DatabaseOperation::AddOrUpdate,
            MNT_TEXT,
            age_days,
        ))?;
        tx.put_journal_entry(&entry(
            180,
            DatabaseOperation::Delete,
            "mntner:         TEST-MNT\n",
            0,
        ))?;
        let mut status = DatabaseStatus::new("TEST", tx.transaction_time());
        status.serial_oldest_journal = Some(100);
        status.serial_newest_journal = Some(200);
        tx.put_database_status(&status)
    })
    .expect("write");
    (Tmp(p), st)
}

fn settings(f: impl FnOnce(&mut SourceQuerySettings)) -> Arc<QuerySettings> {
    let mut s = QuerySettings {
        version: "4.5.4".into(),
        sources: vec!["TEST".into()],
        ..QuerySettings::default()
    };
    let mut src = SourceQuerySettings {
        keep_journal: ConfigValue::Bool(true),
        nrtm_access_list: Some("nrtm".into()),
        nrtm_access_list_unfiltered: Some("unfiltered".into()),
        nrtm_query_serial_range_limit: ConfigValue::Int(200),
        ..SourceQuerySettings::default()
    };
    f(&mut src);
    s.per_source.insert("TEST".into(), src);
    s.access_lists.insert(
        "nrtm".into(),
        vec![rpsl::Ip::parse("192.0.2.0/24", 0).expect("ip")],
    );
    s.access_lists.insert(
        "unfiltered".into(),
        vec![rpsl::Ip::parse("198.51.100.1", 0).expect("ip")],
    );
    Arc::new(s)
}

fn query(st: &Store, settings: &Arc<QuerySettings>, client: &str, q: &str) -> String {
    let mut s = WhoisSession::new(settings.clone(), Arc::new(NrtmServer), client, client);
    let mut out = Vec::new();
    s.query_whois(st, q, &mut out);
    String::from_utf8(out).expect("utf8")
}

fn g(st: &Store, settings: &Arc<QuerySettings>, q: &str) -> String {
    query(st, settings, "192.0.2.1", q)
}

const RANGE_V3: &str = "%START Version: 3 TEST 110-190\n\nADD 120\n\nmntner:         TEST-MNT\ndescr:          description\nnotify:         notify@example.com\nauth:           CRYPT-PW DummyValue  # Filtered for security\n\nDEL 180\n\nmntner:         TEST-MNT\n\n%END TEST";

#[test]
fn serial_ranges() {
    let (_t, st) = setup("ranges", 0);
    let s = settings(|_| {});
    assert_eq!(g(&st, &s, "-g TEST:3:110-190"), format!("{RANGE_V3}\n\n\n"));
    assert_eq!(
        g(&st, &s, "-g test:1:110-190"),
        format!(
            "{}\n\n\n",
            RANGE_V3
                .replace("Version: 3", "Version: 1")
                .replace("ADD 120", "ADD")
                .replace("DEL 180", "DEL")
        )
    );
    assert_eq!(
        g(&st, &s, "-g TEST:3:110-LAST"),
        format!("{}\n\n\n", RANGE_V3.replace("110-190", "110-200"))
    );
    // Nothing in range: header and footer only.
    assert_eq!(
        g(&st, &s, "-g TEST:3:121-179"),
        "%START Version: 3 TEST 121-179\n\n%END TEST\n\n\n"
    );
}

#[test]
fn errors() {
    let (_t, st) = setup("errors", 0);
    let s = settings(|_| {});
    let cases = [
        (
            "-g TEST:3:200-190",
            "Start of the serial range (200) must be lower or equal to end of the serial range (190)",
        ),
        ("-g TEST:3:10-190", "Serials 10 - 100 do not exist"),
        ("-g TEST:3:202-LAST", "Serials 200 - 202 do not exist"),
        ("-g TEST:3:110-300", "Serials 200 - 300 do not exist"),
    ];
    for (q, err) in cases {
        assert_eq!(g(&st, &s, q), format!("%% ERROR: {err}\n\n\n"), "{q}");
    }
    assert_eq!(
        g(&st, &s, "-g TEST:3:201-LAST"),
        "% Warning: there are no newer updates available\n\n\n"
    );
    let s = settings(|x| x.keep_journal = ConfigValue::Bool(false));
    assert_eq!(
        g(&st, &s, "-g TEST:3:110-190"),
        "%% ERROR: No journal kept for this source, unable to serve NRTM queries\n\n\n"
    );
    let s = settings(|x| x.nrtm_query_serial_range_limit = ConfigValue::Int(50));
    assert_eq!(
        g(&st, &s, "-g TEST:3:110-190"),
        "%% ERROR: Serial range requested exceeds maximum range of 50\n\n\n"
    );
    // Not in either access list.
    assert_eq!(
        query(&st, &s, "203.0.113.1", "-g TEST:3:110-190"),
        "%% ERROR: Access denied\n\n\n"
    );
}

#[test]
fn unfiltered_clients_see_hashes_and_real_objects() {
    let (_t, st) = setup("unfiltered", 0);
    let s = settings(|x| {
        x.dummify = rpsl::text::DummifySettings {
            object_classes: vec!["mntner".into()],
            attributes: vec![("descr".into(), "Dummy description".into())],
            remarks: Some("THIS OBJECT IS NOT VALID".into()),
        };
    });
    assert_eq!(
        query(&st, &s, "198.51.100.1", "-g TEST:3:110-190"),
        format!(
            "{}\n\n\n",
            RANGE_V3.replace("DummyValue  # Filtered for security", "foobar")
        )
    );
    assert_eq!(
        g(&st, &s, "-g TEST:3:110-190"),
        format!(
            "{}\n\n\n",
            RANGE_V3
                .replace("description\n", "Dummy description\n")
                .replace(
                    "security\n",
                    "security\nremarks:        THIS OBJECT IS NOT VALID\n"
                )
        )
    );
}

#[test]
fn response_header() {
    let (_t, st) = setup("header", 0);
    let s = settings(|x| {
        x.nrtm_response_header =
            Some("NRTM response header line1\nNRTM response header line2".into())
    });
    assert_eq!(
        g(&st, &s, "-g TEST:3:110-190"),
        format!("%NRTM response header line1\n%NRTM response header line2\n{RANGE_V3}\n\n\n")
    );
}

#[test]
fn days_limit() {
    let (_t, st) = setup("days", 15);
    let s = settings(|x| x.nrtm_query_serial_days_limit = ConfigValue::Int(14));
    assert_eq!(
        g(&st, &s, "-g TEST:3:110-190"),
        "%% ERROR: Requesting serials older than 14 days will be rejected\n\n\n"
    );
    // The first entry at or after the start serial decides.
    assert_eq!(
        g(&st, &s, "-g TEST:3:121-190"),
        "%START Version: 3 TEST 121-190\n\nDEL 180\n\nmntner:         TEST-MNT\n\n%END TEST\n\n\n"
    );
    let s = settings(|x| x.nrtm_query_serial_days_limit = ConfigValue::Int(16));
    assert_eq!(g(&st, &s, "-g TEST:3:110-190"), format!("{RANGE_V3}\n\n\n"));
    let s = settings(|x| x.nrtm_query_serial_days_limit = ConfigValue::Int(14));
    assert_eq!(
        g(&st, &s, "-g TEST:3:181-200"),
        "%% ERROR: There are no journal entries greater than or equal to this serial 181.\n\n\n"
    );
}

/// A session answers each query with the settings it is given before it,
/// as v4's whois worker reads them with `get_setting()` after a SIGHUP:
/// taking a client off `nrtm_access_list_unfiltered` stops unfiltered
/// output on an open `-k` connection at its next query. What v4's
/// `QuerySourceManager` copies when the connection starts stays: the
/// valid sources, and the session's own selection.
#[test]
fn settings_change_reaches_an_open_session() {
    let (_t, st) = setup("reload", 0);
    let mut session =
        WhoisSession::new(settings(|_| {}), Arc::new(NrtmServer), "198.51.100.1", "x");
    let ask = |session: &mut WhoisSession, q: &str| {
        let mut out = Vec::new();
        session.query_whois(&st, q, &mut out);
        String::from_utf8(out).expect("utf8")
    };
    let unfiltered = RANGE_V3.replace("DummyValue  # Filtered for security", "foobar");
    assert_eq!(
        ask(&mut session, "-k"),
        "%  No entries found for the selected source(s).\n\n\n"
    );
    assert_eq!(ask(&mut session, "!sTEST"), "C\n");
    assert_eq!(
        ask(&mut session, "-g TEST:3:110-190"),
        format!("{unfiltered}\n\n\n")
    );
    assert_eq!(ask(&mut session, "-q sources"), "TEST:3:X:100-200\n\n\n");

    // Off the unfiltered list, onto the filtered one; and a new source.
    let mut moved = (*settings(|s| s.nrtm_access_list_unfiltered = None)).clone();
    moved.access_lists.insert(
        "nrtm".into(),
        vec![rpsl::Ip::parse("198.51.100.1", 0).expect("ip")],
    );
    moved.sources.push("NEW".into());
    let moved = Arc::new(moved);
    session.update_settings(moved.clone());
    assert_eq!(
        ask(&mut session, "-g TEST:3:110-190"),
        format!("{RANGE_V3}\n\n\n")
    );
    // NEW was not a source when the connection started.
    assert_eq!(
        ask(&mut session, "-g NEW:3:1-LAST"),
        "%% ERROR: Unknown source: NEW\n\n\n"
    );
    assert_eq!(
        query(&st, &moved, "198.51.100.1", "-g NEW:3:1-LAST"),
        "%% ERROR: Access denied\n\n\n"
    );
    // The source selection and -k survive.
    assert_eq!(ask(&mut session, "!s-lc"), "A5\nTEST\nC\n");

    // Off both lists.
    session.update_settings(settings(|s| {
        s.nrtm_access_list = None;
        s.nrtm_access_list_unfiltered = None;
    }));
    assert_eq!(
        ask(&mut session, "-g TEST:3:110-190"),
        "%% ERROR: Access denied\n\n\n"
    );
    assert_eq!(ask(&mut session, "-q sources"), "TEST:3:N:100-200\n\n\n");
    assert!(session.multiple_command_mode);
}
