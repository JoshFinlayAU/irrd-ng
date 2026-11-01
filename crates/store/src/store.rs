//! [`Store`]: the shared handle, with the single writer thread.

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;

use crate::env::{self, Inner, StoreOptions};
use crate::error::{Result, StoreError};
use crate::read::ReadTx;
use crate::settings::StoreSettings;
use crate::write::{ChangedObjects, RoutePreferenceHook, WriteTx};

type JobFn = Box<dyn FnMut(&mut WriteTx<'_, '_>) -> Result<()> + Send>;
type DoneFn = Box<dyn FnOnce(Result<ChangedObjects>) + Send>;

struct Job {
    run: JobFn,
    done: DoneFn,
    /// Free map space wanted before the job starts.
    reserve: usize,
}

const GIB: usize = 1 << 30;

/// The name of the single writer thread.
pub const WRITER_THREAD_NAME: &str = "store-writer";

/// Most jobs grouped into one LMDB transaction.
const MAX_GROUP: usize = 256;

#[derive(Default)]
struct Shared {
    settings: RwLock<Arc<StoreSettings>>,
    routepref_hook: RwLock<Option<RoutePreferenceHook>>,
    event_listener: RwLock<Option<EventListener>>,
}

/// Called after each commit with `(source, operation)` for every source
/// whose journal grew (`journal_extended`), and by
/// [`Store::publish_event`]: the event stream's publisher.
pub type EventListener = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// The store: open once per process and share (it is cheap to clone).
///
/// Reads run on any thread through [`Store::read`]. Writes are closures
/// sent to one writer thread ([`Store::write`]), which runs each in its own
/// (nested) LMDB write transaction and commits waiting jobs together.
#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
    shared: Arc<Shared>,
    writer: Option<Arc<Writer>>,
}

struct Writer {
    tx: Mutex<Option<Sender<Job>>>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Writer {
    fn drop(&mut self) {
        if let Ok(mut tx) = self.tx.lock() {
            tx.take();
        }
        if let Ok(mut h) = self.handle.lock()
            && let Some(h) = h.take()
        {
            let _ = h.join();
        }
    }
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

/// Size and version information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreInfo {
    /// The store directory.
    pub path: std::path::PathBuf,
    /// The schema version.
    pub schema_version: u32,
    /// The current map size in bytes.
    pub map_size: usize,
    /// Bytes of the data file in use.
    pub used_bytes: usize,
    /// Map sizes over time, as (timestamp, bytes).
    pub map_size_history: Vec<(String, u64)>,
}

impl Store {
    /// Open (creating or migrating as needed) the store.
    pub fn open(options: &StoreOptions, settings: StoreSettings) -> Result<Store> {
        let inner = env::open(options)?;
        let shared = Arc::new(Shared {
            settings: RwLock::new(Arc::new(settings)),
            routepref_hook: RwLock::new(None),
            event_listener: RwLock::new(None),
        });
        let writer = if options.read_only {
            None
        } else {
            let (tx, rx) = mpsc::channel::<Job>();
            let inner2 = inner.clone();
            let shared2 = shared.clone();
            let handle = std::thread::Builder::new()
                .name(WRITER_THREAD_NAME.into())
                .spawn(move || writer_loop(&inner2, &shared2, rx))
                .map_err(|e| StoreError::Io(options.path.clone(), e))?;
            Some(Arc::new(Writer {
                tx: Mutex::new(Some(tx)),
                handle: Mutex::new(Some(handle)),
            }))
        };
        Ok(Store {
            inner,
            shared,
            writer,
        })
    }

    /// Replace the settings (on SIGHUP). Running writes keep the old ones.
    pub fn set_settings(&self, settings: StoreSettings) {
        if let Ok(mut s) = self.shared.settings.write() {
            *s = Arc::new(settings);
        }
    }

    /// The settings in force.
    pub fn settings(&self) -> Arc<StoreSettings> {
        self.shared
            .settings
            .read()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Install the route preference re-evaluation run before each commit
    /// that touched route objects.
    pub fn set_route_preference_hook(&self, hook: Option<RoutePreferenceHook>) {
        if let Ok(mut h) = self.shared.routepref_hook.write() {
            *h = hook;
        }
    }

    /// Install the event stream publisher.
    pub fn set_event_listener(&self, listener: Option<EventListener>) {
        if let Ok(mut l) = self.shared.event_listener.write() {
            *l = listener;
        }
    }

    /// Publish an event other than `journal_extended` (a mirror's
    /// `full_reload`).
    pub fn publish_event(&self, source: &str, operation: &str) {
        let listener = self
            .shared
            .event_listener
            .read()
            .ok()
            .and_then(|l| l.clone());
        if let Some(l) = listener {
            l(source, operation);
        }
    }

    /// Begin a read transaction.
    ///
    /// If another process grew the map beyond this process's mapping,
    /// LMDB refuses new transactions until the mapping is renewed; that is
    /// done here (waiting for this process's other readers) and the
    /// transaction retried.
    pub fn read(&self) -> Result<ReadTx> {
        self.begin_read(false)
    }

    /// Begin a read transaction that may stay open for a long time (a
    /// standby snapshot, an export). While it is open, growing the map
    /// waits for it, as LMDB requires, but queries are not held back
    /// meanwhile: only the write that needed the space waits. Short reads
    /// use [`Store::read`].
    pub fn read_long(&self) -> Result<ReadTx> {
        self.begin_read(true)
    }

    fn begin_read(&self, long: bool) -> Result<ReadTx> {
        match ReadTx::begin(self.inner.clone(), long) {
            Err(e) if is_map_resized(&e) => {
                env::resize(&self.inner, 0)?;
                ReadTx::begin(self.inner.clone(), long)
            }
            r => r,
        }
    }

    /// Grow the map now, if needed, so that at least `bytes` more can be
    /// written without growing it again. Used before a long read: the map
    /// cannot grow while one is open, so a write that needs more space
    /// would wait for it to end.
    pub fn reserve_headroom(&self, bytes: usize) -> Result<()> {
        if self.writer.is_none() {
            return Ok(());
        }
        self.write_reserving(bytes, |_| Ok(())).map(|_| ())
    }

    /// Bytes of the data file in use.
    pub fn used_bytes(&self) -> usize {
        env::used_bytes(&self.inner.env)
    }

    /// Run `f` as one v4 database transaction on the writer thread and
    /// wait for the commit. Returning `Err` from `f` rolls it back.
    ///
    /// `f` may run more than once: when the map is full, the transaction
    /// is aborted, the map grown and `f` run again from the start. Keep
    /// side effects outside the store (logging, I/O) out of it.
    pub fn write<R, F>(&self, f: F) -> Result<R>
    where
        R: Send + 'static,
        F: FnMut(&mut WriteTx<'_, '_>) -> Result<R> + Send + 'static,
    {
        self.write_with_changes(f).map(|(r, _)| r)
    }

    /// [`Store::write`], also returning what changed (for preload and event
    /// stream signalling).
    pub fn write_with_changes<R, F>(&self, f: F) -> Result<(R, ChangedObjects)>
    where
        R: Send + 'static,
        F: FnMut(&mut WriteTx<'_, '_>) -> Result<R> + Send + 'static,
    {
        self.write_reserving(0, f)
    }

    /// [`Store::write_with_changes`], first growing the map so at least
    /// `reserve` bytes are free. Large loads pass an estimate so they do
    /// not hit "map full" and run twice.
    pub fn write_reserving<R, F>(&self, reserve: usize, mut f: F) -> Result<(R, ChangedObjects)>
    where
        R: Send + 'static,
        F: FnMut(&mut WriteTx<'_, '_>) -> Result<R> + Send + 'static,
    {
        let writer = self.writer.as_ref().ok_or(StoreError::ReadOnly)?;
        let slot: Arc<Mutex<Option<R>>> = Arc::new(Mutex::new(None));
        let slot2 = slot.clone();
        let run: JobFn = Box::new(move |tx| {
            let r = f(tx)?;
            if let Ok(mut s) = slot2.lock() {
                *s = Some(r);
            }
            Ok(())
        });
        let (done_tx, done_rx) = mpsc::channel();
        let done: DoneFn = Box::new(move |res| {
            let _ = done_tx.send(res);
        });
        {
            let guard = writer.tx.lock().map_err(|_| StoreError::WriterGone)?;
            let sender = guard.as_ref().ok_or(StoreError::WriterGone)?;
            sender
                .send(Job { run, done, reserve })
                .map_err(|_| StoreError::WriterGone)?;
        }
        let changed = done_rx.recv().map_err(|_| StoreError::WriterGone)??;
        let r = slot
            .lock()
            .map_err(|_| StoreError::WriterGone)?
            .take()
            .ok_or(StoreError::WriterGone)?;
        Ok((r, changed))
    }

    /// Size and version information.
    pub fn info(&self) -> Result<StoreInfo> {
        let rtxn = self.read()?;
        let _ = &rtxn;
        let env_info = self.inner.env.info();
        let txn = self.inner.env.read_txn()?;
        let history = match self
            .inner
            .tables
            .meta
            .get(&txn, env::META_MAP_SIZE_HISTORY)?
        {
            Some(b) => serde_json::from_slice(b).unwrap_or_default(),
            None => Vec::new(),
        };
        let schema_version = env::read_schema_version(&txn, &self.inner.tables)?.unwrap_or(0);
        Ok(StoreInfo {
            path: self.inner.path.clone(),
            schema_version,
            map_size: env_info.map_size,
            used_bytes: env::used_bytes(&self.inner.env),
            map_size_history: history,
        })
    }

    /// Per table: (name, entries, bytes in pages).
    pub fn table_stats(&self) -> Result<Vec<(&'static str, u64, u64)>> {
        let _r = self.read()?;
        let txn = self.inner.env.read_txn()?;
        let mut out = Vec::new();
        for (name, table) in self.inner.tables.named() {
            let s = table.stat(&txn)?;
            out.push((name, s.entries as u64, s.non_free_page_size() as u64));
        }
        Ok(out)
    }

    /// Flush to disk (LMDB commits are already durable unless the
    /// environment was opened with [`StoreOptions::bulk_load`]).
    pub fn sync(&self) -> Result<()> {
        self.inner.env.force_sync()?;
        Ok(())
    }

    /// Start a bulk load of one source (`irrd_load_database`): durably
    /// mark it. The returned guard syncs and clears the mark when finished
    /// or dropped, so only a crash or kill leaves it behind; the next
    /// read-write open then sets the source's `force_reload` and logs.
    pub fn begin_bulk_load(&self, source: &str) -> Result<BulkLoad> {
        self.begin_marker(crate::env::source_marker_key(source), source, false)
    }

    /// Start a bulk load of the whole store (the v4 import). Only
    /// [`BulkLoad::finish`] clears the mark: dropping the guard any other
    /// way (an error, a panic, an early return) syncs what was written but
    /// leaves the mark, as a crash or kill would, so a partial import is
    /// never served. A leftover mark makes every later open fail with
    /// [`StoreError::LoadIncomplete`].
    pub fn begin_whole_store_load(&self, label: &str) -> Result<BulkLoad> {
        self.begin_marker(env::META_LOAD_INCOMPLETE.to_vec(), label, true)
    }

    fn begin_marker(&self, key: Vec<u8>, value: &str, whole_store: bool) -> Result<BulkLoad> {
        let k = key.clone();
        let v = value.as_bytes().to_vec();
        self.write(move |tx| tx.set_meta(&k, &v))?;
        self.sync()?;
        Ok(BulkLoad {
            store: self.clone(),
            key: Some(key),
            whole_store,
        })
    }

    /// The id of the last committed LMDB transaction, from any process.
    /// It changes with every write, which makes it a cheap "did anything
    /// write" check.
    pub fn last_txn_id(&self) -> usize {
        self.inner.env.info().last_txn_id
    }

    /// The replication log state ([`crate::replog`]).
    pub fn replication_state(&self) -> Result<crate::replog::ReplicationState> {
        let r = self.read()?;
        r.with_txn(crate::replog::state)
    }

    /// Start logging every change for standbys, if not yet enabled.
    /// Returns the log id.
    pub fn enable_replication_log(&self) -> Result<String> {
        self.write(|tx| crate::replog::enable(tx.txn, &tx.t))
    }

    /// Stop logging and drop the log. Returns whether it was enabled.
    pub fn disable_replication_log(&self) -> Result<bool> {
        self.write(|tx| crate::replog::disable(tx.txn, &tx.t))
    }

    /// Drop log entries committed before `before`, keeping the newest.
    pub fn trim_replication_log(&self, before: crate::model::Timestamp) -> Result<u64> {
        self.write(move |tx| crate::replog::trim(tx.txn, &tx.t, before.0))
    }

    /// Stored log entries after sequence `after`, up to about `max_bytes`
    /// (at least one if any), with the log id they belong to.
    pub fn replication_entries(
        &self,
        after: u64,
        max_bytes: usize,
    ) -> Result<(Option<String>, crate::replog::StoredEntries)> {
        let r = self.read()?;
        r.with_txn(|txn, t| {
            let id = crate::replog::state(txn, t)?.id;
            Ok((id, crate::replog::entries_after(txn, t, after, max_bytes)?))
        })
    }

    /// Every replicated row from one consistent view, passed to `row` as
    /// (table id, key, value), and the log state of that view. The read
    /// transaction stays open until `row` has seen the last row.
    pub fn replication_snapshot(
        &self,
        on_state: &mut dyn FnMut(&crate::replog::ReplicationState) -> Result<()>,
        row: crate::replog::RowSink<'_>,
    ) -> Result<crate::replog::ReplicationState> {
        // The snapshot's read transaction stays open while the standby
        // takes the rows, which can be minutes for a large store, and the
        // map cannot grow meanwhile. Grow it first, by as much as is in use,
        // so that writes in that time very likely fit; if one does not, it
        // waits for the snapshot (a long reader), and queries carry on.
        self.reserve_headroom(self.used_bytes().max(GIB))?;
        let r = self.read_long()?;
        r.with_txn(|txn, t| {
            let st = crate::replog::state(txn, t)?;
            on_state(&st)?;
            crate::replog::snapshot(txn, t, row)?;
            Ok(st)
        })
    }

    /// On a standby: apply entries of log `id` that continue from the last
    /// one applied. Bypasses `readonly_standby`, which refuses every other
    /// write. Returns the last sequence applied.
    pub fn apply_replication_entries(&self, id: &str, entries: Vec<(u64, Vec<u8>)>) -> Result<u64> {
        let id = id.to_owned();
        self.write(move |tx| crate::replog::apply_entries(tx.txn, &tx.t, &id, &entries))
    }

    /// On a standby: replace every replicated row with a snapshot of log
    /// `id` at `seq`, spooled to `spool`. Returns the rows written.
    pub fn apply_replication_snapshot(
        &self,
        id: &str,
        seq: u64,
        spool: &std::path::Path,
    ) -> Result<u64> {
        let id = id.to_owned();
        let spool = spool.to_path_buf();
        let size = std::fs::metadata(&spool)
            .map(|m| m.len() as usize)
            .unwrap_or(0);
        self.write_reserving(size.saturating_mul(2), move |tx| {
            crate::replog::apply_snapshot(tx.txn, &tx.t, &id, seq, &spool)
        })
        .map(|(rows, _)| rows)
    }

    /// Sources whose interrupted bulk load was found when this store was
    /// opened; their `force_reload` is now set.
    pub fn recovered_interrupted_loads(&self) -> &[String] {
        &self.inner.recovered_interrupted_loads
    }
}

/// An open bulk load: see [`Store::begin_bulk_load`].
#[derive(Debug)]
#[must_use = "dropping it ends the bulk load"]
pub struct BulkLoad {
    store: Store,
    key: Option<Vec<u8>>,
    /// A whole-store load keeps its mark unless finished.
    whole_store: bool,
}

impl BulkLoad {
    /// Sync everything written, then clear the mark and sync again.
    pub fn finish(mut self) -> Result<()> {
        self.end()
    }

    /// End without clearing the mark, as a crash or kill would. Tests only.
    #[doc(hidden)]
    pub fn abandon_for_tests(mut self) {
        self.key = None;
    }

    fn end(&mut self) -> Result<()> {
        let Some(key) = self.key.take() else {
            return Ok(());
        };
        self.store.sync()?;
        self.store.write(move |tx| tx.delete_meta(&key))?;
        self.store.sync()
    }
}

impl Drop for BulkLoad {
    /// Dropped without [`BulkLoad::finish`]. A per-source load ends here
    /// too: committed work is synced and the mark cleared. A whole-store
    /// load syncs what was written and keeps the mark, so the store
    /// refuses to open until it is re-imported.
    fn drop(&mut self) {
        let r = if self.whole_store {
            self.key = None;
            self.store.sync()
        } else {
            self.end()
        };
        if let Err(e) = r {
            tracing::error!(target: crate::env::LOG_TARGET, "{e}");
        }
    }
}

fn writer_loop(inner: &Inner, shared: &Shared, rx: Receiver<Job>) {
    while let Ok(first) = rx.recv() {
        let mut batch = vec![first];
        while batch.len() < MAX_GROUP {
            match rx.try_recv() {
                Ok(j) => batch.push(j),
                Err(_) => break,
            }
        }
        let settings = shared
            .settings
            .read()
            .map(|s| s.clone())
            .unwrap_or_default();
        let hook = shared.routepref_hook.read().ok().and_then(|h| *h);
        let results = run_batch(inner, &settings, hook, &mut batch);
        // v4's publish_event_stream(): right after commit, before the
        // caller goes on.
        let listener = shared.event_listener.read().ok().and_then(|l| l.clone());
        if let Some(l) = listener {
            for changed in results.iter().flatten() {
                for source in &changed.sources_with_new_serials {
                    l(source, "journal_extended");
                }
            }
        }
        for (job, res) in batch.into_iter().zip(results) {
            (job.done)(res);
        }
    }
}

enum Attempt {
    Done(Vec<Result<ChangedObjects>>),
    MapFull,
}

fn run_batch(
    inner: &Inner,
    settings: &StoreSettings,
    hook: Option<RoutePreferenceHook>,
    batch: &mut [Job],
) -> Vec<Result<ChangedObjects>> {
    let reserve = batch.iter().map(|j| j.reserve).max().unwrap_or(0);
    loop {
        if let Err(e) = ensure_headroom(inner, reserve) {
            return fail_all(batch.len(), &e);
        }
        match attempt(inner, settings, hook, batch) {
            Ok(Attempt::Done(results)) => return results,
            Ok(Attempt::MapFull) => {
                let map = inner.env.info().map_size;
                let new = env::grown_size(map, map);
                if let Err(e) = env::resize(inner, new) {
                    return fail_all(batch.len(), &e);
                }
            }
            Err(e) if is_map_resized(&e) => {
                if let Err(e) = env::resize(inner, 0) {
                    return fail_all(batch.len(), &e);
                }
            }
            Err(e) => return fail_all(batch.len(), &e),
        }
    }
}

fn is_map_resized(e: &StoreError) -> bool {
    matches!(
        e,
        StoreError::Lmdb(heed::Error::Mdb(heed::MdbError::MapResized))
    )
}

fn fail_all(n: usize, e: &StoreError) -> Vec<Result<ChangedObjects>> {
    (0..n)
        .map(|_| Err(StoreError::Aborted(e.to_string())))
        .collect()
}

fn ensure_headroom(inner: &Inner, reserve: usize) -> Result<()> {
    let used = env::used_bytes(&inner.env);
    let map = inner.env.info().map_size;
    if env::needs_growth(used, map) || map.saturating_sub(used) < reserve {
        env::resize(inner, env::grown_size(used + reserve, map))?;
    }
    Ok(())
}

fn attempt(
    inner: &Inner,
    settings: &StoreSettings,
    hook: Option<RoutePreferenceHook>,
    batch: &mut [Job],
) -> Result<Attempt> {
    let mut parent = inner.env.write_txn()?;
    env::record_map_size(&mut parent, &inner.tables, inner.env.info().map_size)?;
    let repl = crate::replog::enabled(&parent, &inner.tables)?;
    let mut results = Vec::with_capacity(batch.len());
    if batch.len() == 1 {
        // A single job runs in the top-level transaction: large loads
        // avoid the cost of a nested transaction.
        let job = &mut batch[0];
        let capture = crate::replog::begin(repl, inner.bulk_load);
        let mut tx = WriteTx::new(&mut parent, inner.tables, settings, hook);
        let r = (job.run)(&mut tx).and_then(|_| tx.finish());
        drop(tx);
        let r = r.and_then(|changed| {
            capture.commit(&mut parent, &inner.tables)?;
            Ok(changed)
        });
        match r {
            Err(e) if e.is_map_full() => {
                parent.abort();
                return Ok(Attempt::MapFull);
            }
            Err(e) => {
                parent.abort();
                return Ok(Attempt::Done(vec![Err(e)]));
            }
            Ok(changed) => results.push(Ok(changed)),
        }
    } else {
        for job in batch.iter_mut() {
            let mut nested = inner.env.nested_write_txn(&mut parent)?;
            let capture = crate::replog::begin(repl, inner.bulk_load);
            let mut tx = WriteTx::new(&mut nested, inner.tables, settings, hook);
            let r = (job.run)(&mut tx).and_then(|_| tx.finish());
            drop(tx);
            let r = r.and_then(|changed| {
                capture.commit(&mut nested, &inner.tables)?;
                Ok(changed)
            });
            match r {
                Ok(changed) => match nested.commit() {
                    Ok(()) => results.push(Ok(changed)),
                    Err(heed::Error::Mdb(heed::MdbError::MapFull)) => {
                        parent.abort();
                        return Ok(Attempt::MapFull);
                    }
                    Err(e) => results.push(Err(e.into())),
                },
                Err(e) if e.is_map_full() => {
                    nested.abort();
                    parent.abort();
                    return Ok(Attempt::MapFull);
                }
                Err(e) => {
                    nested.abort();
                    results.push(Err(e));
                }
            }
        }
    }
    match parent.commit() {
        Ok(()) => Ok(Attempt::Done(results)),
        Err(heed::Error::Mdb(heed::MdbError::MapFull)) => Ok(Attempt::MapFull),
        Err(e) => Err(e.into()),
    }
}
