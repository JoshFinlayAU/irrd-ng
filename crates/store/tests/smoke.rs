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

#[test]
fn interrupted_bulk_load_is_refused() {
    let dir = TempDir::new("bulk");
    let mut o = store::StoreOptions::new(&dir.0);
    o.initial_map_size = 64 << 20;
    o.bulk_load = true;
    {
        let store = store::Store::open(&o, settings(&[])).expect("open");
        store.begin_bulk_load("RADB").expect("begin");
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
        // Dropped without finish_bulk_load: as if the process died.
    }
    for read_only in [false, true] {
        let mut o2 = store::StoreOptions::new(&dir.0);
        o2.read_only = read_only;
        let e = store::Store::open(&o2, settings(&[])).expect_err("incomplete");
        assert!(
            matches!(e, store::StoreError::LoadIncomplete { ref load_source, .. } if load_source == "RADB")
        );
        assert!(
            e.to_string()
                .contains("incomplete bulk load of source RADB")
        );
    }
}

#[test]
fn finished_bulk_load_opens() {
    let dir = TempDir::new("bulkok");
    let mut o = store::StoreOptions::new(&dir.0);
    o.initial_map_size = 64 << 20;
    o.bulk_load = true;
    {
        let store = store::Store::open(&o, settings(&[])).expect("open");
        store.begin_bulk_load("RADB").expect("begin");
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
        store.finish_bulk_load().expect("finish");
    }
    let store = open(&dir, settings(&[]));
    assert_eq!(
        store.read().expect("r").view().object_count().expect("c"),
        1
    );
}
