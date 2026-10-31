mod common;

use common::*;
use store::JournalEntryOrigin;

#[test]
fn upsert_read_back_and_reopen() {
    let dir = TempDir::new("smoke");
    {
        let store = open(&dir, settings(&[]));
        store
            .write(|tx| {
                tx.upsert_rpsl_object(
                    &route(
                        "192.0.2.0/24AS65537",
                        "TEST",
                        "192.0.2.0/24",
                        65537,
                        "MNT-A",
                    ),
                    JournalEntryOrigin::Mirror,
                    None,
                    None,
                )
            })
            .expect("write");
        let r = store.read().expect("read");
        let v = r.view();
        let o = v
            .object("TEST", "route", "192.0.2.0/24AS65537")
            .expect("get")
            .expect("present");
        assert_eq!(o.object_text, "object-text");
        assert_eq!(
            v.ids_by_lookup("mnt-by", Some("MNT-A"))
                .expect("lookup")
                .len(),
            1
        );
        assert_eq!(
            v.routes_for_origin("TEST", 65537, Some(4))
                .expect("origin")
                .len(),
            1
        );
    }
    let store = open(&dir, settings(&[]));
    let r = store.read().expect("read");
    assert_eq!(r.view().object_count().expect("count"), 1);
}

fn bulk_options(dir: &TempDir) -> store::StoreOptions {
    let mut o = store::StoreOptions::new(&dir.0);
    o.initial_map_size = 64 << 20;
    o.bulk_load = true;
    o
}

fn status_settings() -> store::StoreSettings {
    settings(&[])
}

/// Load one source in bulk mode, then the guard `f` decides how it ends.
fn bulk_load_radb(dir: &TempDir, end: impl FnOnce(store::BulkLoad)) {
    let store = store::Store::open(&bulk_options(dir), status_settings()).expect("open");
    // A committed earlier state: another source, and RADB's status row.
    store
        .write(|tx| {
            tx.upsert_rpsl_object(
                &simple("AS-OTHER", "as-set", "OTHER"),
                JournalEntryOrigin::Mirror,
                None,
                None,
            )?;
            tx.record_serial_seen("RADB", 5)
        })
        .expect("seed");
    let bulk = store.begin_bulk_load("RADB").expect("begin");
    store
        .write(|tx| {
            tx.upsert_rpsl_object(
                &simple("AS-X", "as-set", "RADB"),
                JournalEntryOrigin::Mirror,
                None,
                None,
            )
        })
        .expect("write");
    // The load then fails in-process: its transaction aborts.
    let e = store.write(|tx| {
        tx.upsert_rpsl_object(
            &simple("AS-Y", "as-set", "RADB"),
            JournalEntryOrigin::Mirror,
            None,
            None,
        )?;
        Err::<(), _>(store::StoreError::Aborted("parse error".into()))
    });
    assert!(e.is_err());
    end(bulk);
}

#[test]
fn aborted_bulk_load_leaves_no_marker() {
    let dir = TempDir::new("bulkabort");
    // Dropping the guard on an error path syncs and clears the marker.
    bulk_load_radb(&dir, drop);
    let store = open(&dir, status_settings());
    assert!(store.recovered_interrupted_loads().is_empty());
    let r = store.read().expect("r");
    assert!(
        !r.view()
            .database_status("RADB")
            .expect("s")
            .expect("row")
            .force_reload
    );
    assert_eq!(r.view().object_count().expect("c"), 2);
}

#[test]
fn finished_bulk_load_leaves_no_marker() {
    let dir = TempDir::new("bulkok");
    bulk_load_radb(&dir, |b| b.finish().expect("finish"));
    let store = open(&dir, status_settings());
    assert!(store.recovered_interrupted_loads().is_empty());
}

#[test]
fn leftover_source_marker_sets_force_reload_and_logs() {
    let dir = TempDir::new("bulkcrash");
    // A kill or crash: the guard never runs.
    bulk_load_radb(&dir, store::BulkLoad::abandon_for_tests);

    let logs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let sink = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || LogSink(sink.clone()))
        .with_ansi(false)
        .finish();
    let store = tracing::subscriber::with_default(subscriber, || {
        // Read-only opens still serve, and only report.
        let mut ro = store::StoreOptions::new(&dir.0);
        ro.read_only = true;
        drop(store::Store::open(&ro, status_settings()).expect("read-only open"));
        open(&dir, status_settings())
    });
    assert_eq!(store.recovered_interrupted_loads(), ["RADB".to_owned()]);
    let text = String::from_utf8(logs.lock().expect("logs").clone()).expect("utf8");
    assert!(
        text.contains("A bulk load of source RADB was interrupted"),
        "{text}"
    );
    {
        let r = store.read().expect("r");
        let v = r.view();
        assert!(
            v.database_status("RADB")
                .expect("s")
                .expect("row")
                .force_reload
        );
        // Everything else is still served.
        assert!(
            v.object("OTHER", "as-set", "AS-OTHER")
                .expect("q")
                .is_some()
        );
    }
    drop(store);
    // Handled once: the marker is gone.
    let store = open(&dir, status_settings());
    assert!(store.recovered_interrupted_loads().is_empty());
}

#[derive(Clone)]
struct LogSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("logs").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn leftover_whole_store_marker_refuses() {
    let dir = TempDir::new("bulkwhole");
    {
        let store = store::Store::open(&bulk_options(&dir), status_settings()).expect("open");
        let bulk = store
            .begin_whole_store_load("import --from-postgres")
            .expect("begin");
        store
            .write(|tx| {
                tx.upsert_rpsl_object(
                    &simple("AS-X", "as-set", "RADB"),
                    JournalEntryOrigin::Mirror,
                    None,
                    None,
                )
            })
            .expect("write");
        bulk.abandon_for_tests();
    }
    for read_only in [false, true] {
        let mut o = store::StoreOptions::new(&dir.0);
        o.read_only = read_only;
        let e = store::Store::open(&o, status_settings()).expect_err("incomplete");
        assert!(
            matches!(e, store::StoreError::LoadIncomplete { ref load_source, .. } if load_source == "import --from-postgres")
        );
        assert!(e.to_string().contains("incomplete bulk load"));
    }
}

#[test]
fn whole_store_load_dropped_on_error_keeps_marker() {
    let dir = TempDir::new("bulkwholedrop");
    {
        let store = store::Store::open(&bulk_options(&dir), status_settings()).expect("open");
        let bulk = store.begin_whole_store_load("<all>").expect("begin");
        store
            .write(|tx| {
                tx.upsert_rpsl_object(
                    &simple("AS-X", "as-set", "RADB"),
                    JournalEntryOrigin::Mirror,
                    None,
                    None,
                )
            })
            .expect("write");
        // An error path: the guard is dropped without finish().
        drop(bulk);
    }
    let e = store::Store::open(&bulk_options(&dir), status_settings()).expect_err("incomplete");
    assert!(
        matches!(e, store::StoreError::LoadIncomplete { ref load_source, .. } if load_source == "<all>")
    );
}

#[test]
fn finished_whole_store_load_opens() {
    let dir = TempDir::new("bulkwholeok");
    {
        let store = store::Store::open(&bulk_options(&dir), status_settings()).expect("open");
        let bulk = store.begin_whole_store_load("<all>").expect("begin");
        bulk.finish().expect("finish");
    }
    drop(open(&dir, status_settings()));
}

/// Raw rows for the prune tests.
fn raw_object(source: &str, class: &str, pk: &str) -> store::RpslObjectRow {
    store::RpslObjectRow {
        pk: store::Uuid::new_v4(),
        rpsl_pk: pk.to_owned(),
        source: source.to_owned(),
        object_class: class.to_owned(),
        parsed_data: store::Json::canonical(r#"{"mnt-by": ["MNT-P"]}"#).expect("json"),
        object_text: format!("{class}: {pk}\nmnt-by: MNT-P\nsource: {source}\n"),
        ip_version: None,
        ip_first: None,
        ip_last: None,
        prefix_length: None,
        prefix: None,
        asn_first: None,
        asn_last: None,
        rpki_status: store::RpkiStatus::NotFound,
        scopefilter_status: store::ScopeFilterStatus::InScope,
        route_preference_status: store::RoutePreferenceStatus::Visible,
        created: store::Timestamp(0),
        updated: store::Timestamp(0),
    }
}

fn keys(store: &store::Store) -> Vec<String> {
    let r = store.read().expect("r");
    r.view()
        .objects(None, None)
        .expect("objects")
        .map(|o| {
            let (_, o) = o.expect("o");
            format!("{}/{}/{}", o.source, o.object_class, o.rpsl_pk)
        })
        .collect()
}

#[test]
fn prune_objects_by_key_range() {
    let dir = TempDir::new("prune");
    let store = open(&dir, status_settings());
    store
        .write(|tx| {
            for (s, c, p) in [
                ("A", "mntner", "M1"),
                ("A", "mntner", "M2"),
                ("A", "person", "P1"),
                ("B", "mntner", "M1"),
                ("B", "mntner", "M3"),
                ("C", "route", "R1"),
            ] {
                tx.put_rpsl_object(&raw_object(s, c, p))?;
            }
            Ok(())
        })
        .expect("seed");
    // First source batch keeps A/mntner/M1 and A/person/P1: A/mntner/M2,
    // inside the range, goes; B and C, beyond it, stay for now.
    let p1 = store
        .write(|tx| {
            tx.prune_rpsl_objects(None, &[("A", "mntner", "M1"), ("A", "person", "P1")], false)
        })
        .expect("prune 1");
    assert_eq!(p1.deleted, 1);
    assert_eq!(
        keys(&store),
        [
            "A/mntner/M1",
            "A/person/P1",
            "B/mntner/M1",
            "B/mntner/M3",
            "C/route/R1"
        ]
    );
    // An empty batch moves nothing.
    let after = p1.through.clone();
    let p2 = store
        .write(move |tx| tx.prune_rpsl_objects(after.as_deref(), &[], false))
        .expect("prune empty");
    assert_eq!((p2.deleted, &p2.through), (0, &p1.through));
    // The last batch keeps B/mntner/M3, then the end of the stream drops
    // everything after it.
    let after = p1.through;
    let p3 = store
        .write(move |tx| tx.prune_rpsl_objects(after.as_deref(), &[("B", "mntner", "M3")], false))
        .expect("prune 3");
    assert_eq!(p3.deleted, 1);
    let after = p3.through;
    let p4 = store
        .write(move |tx| tx.prune_rpsl_objects(after.as_deref(), &[], true))
        .expect("prune end");
    assert_eq!(p4.deleted, 1);
    assert_eq!(keys(&store), ["A/mntner/M1", "A/person/P1", "B/mntner/M3"]);
    // Index entries went with the rows.
    let r = store.read().expect("r");
    assert_eq!(
        r.view()
            .ids_by_lookup("mnt-by", Some("MNT-P"))
            .expect("l")
            .len(),
        3
    );
}

#[test]
fn prune_journal_and_roas_to_end_on_empty_source() {
    let dir = TempDir::new("prunejr");
    let store = open(&dir, status_settings());
    store
        .write(|tx| {
            for (n, g) in [(1, 10), (2, 11), (3, 12)] {
                tx.put_journal_entry(&store::JournalEntry {
                    pk: store::Uuid::new_v4(),
                    serial_global: g,
                    rpsl_pk: "AS-X".into(),
                    source: "A".into(),
                    origin: JournalEntryOrigin::Mirror,
                    serial_nrtm: n,
                    operation: store::DatabaseOperation::AddOrUpdate,
                    object_class: "as-set".into(),
                    object_text: "as-set: AS-X\n".into(),
                    timestamp: store::Timestamp(0),
                })?;
            }
            for len in [24u8, 25] {
                tx.put_roa(&store::RoaRow {
                    pk: store::Uuid::new_v4(),
                    prefix: store::IpPrefix::new("192.0.2.0".parse().expect("ip"), len).expect("p"),
                    asn: 65000,
                    max_length: 25,
                    trust_anchor: None,
                    ip_version: 4,
                    created: store::Timestamp(0),
                })?;
            }
            Ok(())
        })
        .expect("seed");
    let (j, r) = store
        .write(|tx| {
            let j = tx.prune_journal(None, &[("A", 2)], true)?;
            let r = tx.prune_roas(None, &[], true)?;
            Ok((j.deleted, r.deleted))
        })
        .expect("prune");
    assert_eq!((j, r), (2, 2));
    let rt = store.read().expect("r");
    let v = rt.view();
    assert!(v.journal_entry("A", 2).expect("j").is_some());
    assert!(v.journal_entry("A", 1).expect("j").is_none());
    // The serial_global index lost the deleted entries too.
    let globals: Vec<i64> = v
        .journal_by_serial_global(0)
        .expect("g")
        .map(|e| e.expect("e").serial_global)
        .collect();
    assert_eq!(globals, [11]);
    assert!(v.roas().expect("roas").is_empty());
}
