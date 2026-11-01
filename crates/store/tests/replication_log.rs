//! The replication log as the store keeps it: nothing while disabled, one
//! entry per committed write, a resync for bulk loads, and trimming.

mod common;

use common::*;
use store::replog::{Body, Entry};
use store::{JournalEntryOrigin, Store, StoreOptions, Timestamp};

fn write_one(store: &Store, pk: &str) {
    let o = simple(pk, "mntner", "TEST");
    store
        .write(move |tx| tx.upsert_rpsl_object(&o, JournalEntryOrigin::AuthChange, None, None))
        .expect("write");
}

#[test]
fn log_follows_enable_bulk_load_and_trim() {
    let tmp = TempDir::new("replog");
    let store = open(&tmp, settings(&[]));
    write_one(&store, "MNT-A");
    let st = store.replication_state().expect("state");
    assert_eq!((st.id, st.last_seq), (None, 0), "disabled: nothing logged");

    let id = store.enable_replication_log().expect("enable");
    assert_eq!(store.enable_replication_log().expect("again"), id);
    write_one(&store, "MNT-B");
    // A rolled-back write logs nothing.
    let _ = store.write(|tx| {
        tx.upsert_rpsl_object(
            &simple("MNT-X", "mntner", "TEST"),
            JournalEntryOrigin::AuthChange,
            None,
            None,
        )?;
        Err::<(), _>(store::StoreError::Aborted("no".into()))
    });
    let (log_id, entries) = store.replication_entries(0, usize::MAX).expect("entries");
    assert_eq!(log_id.as_deref(), Some(id.as_str()));
    assert_eq!(entries.len(), 1);
    let Body::Ops(ops) = Entry::decode(&entries[0].1).expect("decode").body else {
        panic!("expected ops");
    };
    assert!(ops.len() > 3, "object, indexes and meta rows: {ops:?}");
    drop(store);

    // Another process loading in bulk mode logs a resync.
    let mut o = StoreOptions::new(&tmp.0);
    o.bulk_load = true;
    let bulk = Store::open(&o, settings(&[])).expect("bulk open");
    write_one(&bulk, "MNT-C");
    drop(bulk);
    let store = open(&tmp, settings(&[]));
    let (_, entries) = store.replication_entries(1, usize::MAX).expect("entries");
    assert_eq!(entries.len(), 1);
    assert!(Entry::is_resync(&entries[0].1).expect("resync"));
    assert_eq!(store.replication_state().expect("state").last_seq, 2);

    // Trimming keeps the newest entry, and sequence numbers carry on.
    let future = Timestamp(Timestamp::now().0 + 1_000_000);
    assert_eq!(store.trim_replication_log(future).expect("trim"), 1);
    write_one(&store, "MNT-D");
    let st = store.replication_state().expect("state");
    assert_eq!((st.first_seq, st.last_seq), (Some(2), 3));

    // Disabling drops the log; enabling again starts a new log id.
    assert!(store.disable_replication_log().expect("disable"));
    write_one(&store, "MNT-E");
    let st = store.replication_state().expect("state");
    assert_eq!((st.id, st.first_seq, st.last_seq), (None, None, 3));
    assert_ne!(store.enable_replication_log().expect("enable"), id);
}
