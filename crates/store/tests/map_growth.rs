//! Growing the map while long read transactions are open.

mod common;

use std::sync::mpsc;
use std::time::Duration;

use common::TempDir;

fn small_store(dir: &TempDir) -> store::Store {
    let mut o = store::StoreOptions::new(&dir.0);
    o.initial_map_size = 16 << 20;
    store::Store::open(&o, store::StoreSettings::default()).expect("open")
}

/// A resize waits for a long reader, but queries are answered meanwhile;
/// once the long reader ends, the resize and the write that wanted it go
/// through.
#[test]
fn resize_waits_for_a_long_reader_without_holding_back_queries() {
    let dir = TempDir::new("long-reader");
    let store = small_store(&dir);
    let before = store.info().expect("info").map_size;
    let long = store.read_long().expect("long read");

    let (done_tx, done_rx) = mpsc::channel();
    let s = store.clone();
    let writer = std::thread::spawn(move || {
        s.reserve_headroom(before * 4).expect("reserve");
        let _ = done_tx.send(());
    });
    // The write needs a bigger map, so it waits for the long reader.
    assert!(done_rx.recv_timeout(Duration::from_millis(300)).is_err());

    // A query meanwhile is not held back.
    let (q_tx, q_rx) = mpsc::channel();
    let s = store.clone();
    std::thread::spawn(move || {
        let r = s.read().expect("short read");
        let _ = r.view().max_serial_global();
        let _ = q_tx.send(());
    });
    q_rx.recv_timeout(Duration::from_secs(5))
        .expect("a query during a pending resize is answered");

    drop(long);
    done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the write goes through once the long reader ends");
    writer.join().expect("writer thread");
    assert!(store.info().expect("info").map_size >= before * 4);
}

/// A short reader still holds a resize back until it ends, and readers
/// arriving meanwhile wait for the resize.
#[test]
fn resize_waits_for_short_readers() {
    let dir = TempDir::new("short-reader");
    let store = small_store(&dir);
    let before = store.info().expect("info").map_size;
    let short = store.read().expect("read");
    let (done_tx, done_rx) = mpsc::channel();
    let s = store;
    let writer = std::thread::spawn(move || {
        s.reserve_headroom(before * 4).expect("reserve");
        let _ = done_tx.send(());
    });
    assert!(done_rx.recv_timeout(Duration::from_millis(300)).is_err());
    drop(short);
    done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("resized after the reader ended");
    writer.join().expect("writer thread");
}

/// Serving a snapshot grows the map first, so writes during it have at
/// least as much room as the store already uses.
#[test]
fn snapshot_grows_the_map_before_it_starts() {
    let dir = TempDir::new("snapshot-headroom");
    let store = small_store(&dir);
    store.enable_replication_log().expect("enable");
    let mut seen = None;
    store
        .replication_snapshot(
            &mut |_| {
                // `info` takes a short read, which a long one allows.
                seen = Some(store.info().expect("info"));
                Ok(())
            },
            &mut |_, _, _| Ok(()),
        )
        .expect("snapshot");
    let info = seen.expect("state seen");
    assert!(info.map_size - info.used_bytes >= info.used_bytes.max(1 << 30));
}
