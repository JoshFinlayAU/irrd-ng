//! Growing the map while long read transactions are open.

mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
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

/// Set (to the store directory and a row name prefix) in the child
/// process of [`map_grown_by_another_process_is_renewed_between_transactions`].
const GROW_CHILD_DIR: &str = "IRRD_NG_TEST_GROW_MAP_DIR";
const GROW_CHILD_PREFIX: &str = "IRRD_NG_TEST_GROW_MAP_PREFIX";
const CHILD_ROWS: usize = 24;
const CHILD_ROW_BYTES: usize = 1 << 20;

fn small_step_options(path: &std::path::Path) -> store::StoreOptions {
    let mut o = store::StoreOptions::new(path);
    o.initial_map_size = 4 << 20;
    o.growth_step = 1 << 20;
    o
}

fn setting(name: String, value: String) -> store::SettingRow {
    store::SettingRow {
        name,
        value: Some(value),
        created: store::Timestamp::now(),
    }
}

/// The child half: as `irrd_load_database` would, another process opens
/// the store and writes far beyond the first process's mapping, growing
/// the map. Does nothing unless run as that child.
#[test]
fn grow_map_child() {
    let (Some(dir), Some(prefix)) = (
        std::env::var_os(GROW_CHILD_DIR),
        std::env::var(GROW_CHILD_PREFIX).ok(),
    ) else {
        return;
    };
    let store = store::Store::open(
        &small_step_options(std::path::Path::new(&dir)),
        store::StoreSettings::default(),
    )
    .expect("child open");
    for i in 0..CHILD_ROWS {
        let value = "x".repeat(CHILD_ROW_BYTES);
        let name = format!("{prefix}-{i}");
        store
            .write(move |tx| tx.put_setting(&setting(name.clone(), value.clone())))
            .expect("child write");
    }
}

fn run_grow_child(dir: &TempDir, prefix: &str) {
    let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "grow_map_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(GROW_CHILD_DIR, &dir.0)
        .env(GROW_CHILD_PREFIX, prefix)
        .status()
        .expect("run child");
    assert!(status.success(), "child: {status}");
}

/// Wait until `counter` has moved on by more than 10 from `from`.
fn progresses(counter: &AtomicUsize, from: usize) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while counter.load(Ordering::Relaxed) <= from + 10 {
        if std::time::Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

/// Another process grows the map while this one reads and writes. LMDB
/// then refuses new transactions here (`MDB_MAP_RESIZED`) until the
/// mapping is renewed, which must not overlap any transaction of this
/// process, read or write: readers hand the renewal to the writer thread
/// (the store asserts in debug builds that only the writer thread
/// resizes a read-write store), and reads and writes carry on.
///
/// The first growth happens while this process only reads, so readers
/// meet the error; the second while it also writes as fast as it can.
#[test]
fn map_grown_by_another_process_is_renewed_between_transactions() {
    let dir = TempDir::new("grown-by-other");
    let store = store::Store::open(&small_step_options(&dir.0), store::StoreSettings::default())
        .expect("open");
    store
        .write(|tx| tx.put_setting(&setting("parent".into(), "0".into())))
        .expect("first write");
    let before = store.info().expect("info").map_size;

    let stop = Arc::new(AtomicBool::new(false));
    let writing = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for _ in 0..4 {
        let (s, stop, reads) = (store.clone(), stop.clone(), reads.clone());
        threads.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let r = s.read().expect("read during growth");
                let rows = r.view().settings().expect("settings");
                assert!(rows.iter().any(|row| row.name == "parent"));
                reads.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    {
        let (s, stop, writing, writes) =
            (store.clone(), stop.clone(), writing.clone(), writes.clone());
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                if !writing.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                n += 1;
                let v = n.to_string();
                s.write(move |tx| tx.put_setting(&setting("parent".into(), v.clone())))
                    .expect("write during growth");
                writes.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    // Grown while only reading.
    run_grow_child(&dir, "first");
    assert!(progresses(&reads, reads.load(Ordering::Relaxed)));
    let after_first = store.info().expect("info").map_size;
    assert!(after_first >= CHILD_ROWS * CHILD_ROW_BYTES);

    // Grown while reading and writing.
    writing.store(true, Ordering::Relaxed);
    assert!(progresses(&writes, writes.load(Ordering::Relaxed)));
    run_grow_child(&dir, "second");
    assert!(progresses(&reads, reads.load(Ordering::Relaxed)));
    assert!(progresses(&writes, writes.load(Ordering::Relaxed)));

    stop.store(true, Ordering::Relaxed);
    for t in threads {
        t.join().expect("no reader or writer failed");
    }

    // This process now maps everything the child wrote.
    let info = store.info().expect("info");
    assert!(info.map_size > before);
    assert!(info.map_size >= 2 * CHILD_ROWS * CHILD_ROW_BYTES);
    let r = store.read().expect("read");
    let rows = r.view().settings().expect("settings");
    for prefix in ["first-", "second-"] {
        assert_eq!(
            rows.iter()
                .filter(|row| row.name.starts_with(prefix))
                .count(),
            CHILD_ROWS
        );
    }
}
