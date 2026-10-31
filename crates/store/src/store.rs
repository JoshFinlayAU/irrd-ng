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

/// Most jobs grouped into one LMDB transaction.
const MAX_GROUP: usize = 256;

#[derive(Default)]
struct Shared {
    settings: RwLock<Arc<StoreSettings>>,
    routepref_hook: RwLock<Option<RoutePreferenceHook>>,
}

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
        });
        let writer = if options.read_only {
            None
        } else {
            let (tx, rx) = mpsc::channel::<Job>();
            let inner2 = inner.clone();
            let shared2 = shared.clone();
            let handle = std::thread::Builder::new()
                .name("store-writer".into())
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

    /// Begin a read transaction.
    pub fn read(&self) -> Result<ReadTx> {
        ReadTx::begin(self.inner.clone())
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
    /// environment was opened without sync).
    pub fn sync(&self) -> Result<()> {
        self.inner.env.force_sync()?;
        Ok(())
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
    let mut results = Vec::with_capacity(batch.len());
    if batch.len() == 1 {
        // A single job runs in the top-level transaction: large loads
        // avoid the cost of a nested transaction.
        let job = &mut batch[0];
        let mut tx = WriteTx::new(&mut parent, inner.tables, settings, hook);
        let r = (job.run)(&mut tx).and_then(|_| tx.finish());
        drop(tx);
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
            let mut tx = WriteTx::new(&mut nested, inner.tables, settings, hook);
            let r = (job.run)(&mut tx).and_then(|_| tx.finish());
            drop(tx);
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
