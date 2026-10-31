//! The LMDB environment: tables, schema version, migrations and map size.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};

use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions, RoTxn, RwTxn, WithoutTls};

use crate::error::{Result, StoreError};
use crate::messages;

/// The on-disk schema version this build reads and writes.
///
/// Bump it for any change to a record layout, key encoding or table set,
/// add a [`Migration`] from the previous version, and commit a fixture
/// environment of the new version next to the old one (see
/// `tests/schema_fixture.rs`).
pub const SCHEMA_VERSION: u32 = 1;

pub(crate) type Table = Database<'static, Bytes, Bytes>;

macro_rules! tables {
    ($($field:ident = $name:literal),+ $(,)?) => {
        /// Every table in the environment.
        #[derive(Debug, Clone, Copy)]
        pub(crate) struct Tables {
            $(pub(crate) $field: Table),+
        }

        /// Table names, for diagnostics and tests.
        pub const TABLE_NAMES: &[&str] = &[$($name),+];

        const TABLE_COUNT: usize = [$($name),+].len();

        impl Tables {
            pub(crate) fn named(&self) -> Vec<(&'static str, Table)> {
                vec![$(($name, self.$field)),+]
            }

            fn from_array(a: [Table; TABLE_COUNT]) -> Self {
                let mut it = a.into_iter();
                Tables {
                    // The array has exactly one entry per field.
                    $($field: it.next().unwrap_or_else(|| unreachable!())),+
                }
            }
        }
    };
}

fn create_tables(env: &Env<WithoutTls>) -> Result<Tables> {
    let wtxn = env.write_txn()?;
    let arr = env
        .create_databases_and_commit(wtxn, |opener, wtxn| -> Result<_> {
            let mut v = Vec::with_capacity(TABLE_COUNT);
            for name in TABLE_NAMES {
                v.push(opener.create_database::<Bytes, Bytes>(wtxn, Some(name))?);
            }
            let arr: [Database<'_, Bytes, Bytes>; TABLE_COUNT] = v
                .try_into()
                .map_err(|_| StoreError::Corrupt("table list"))?;
            Ok(heed::CommitOrAbort::<_, ()>::Commit(arr))
        })?
        .unwrap_commit();
    Ok(Tables::from_array(arr))
}

fn open_tables(env: &Env<WithoutTls>) -> Result<Option<Tables>> {
    let rtxn = env.read_txn()?;
    let arr = env.open_databases_and_commit(rtxn, |opener, rtxn| -> Result<_> {
        let mut v = Vec::with_capacity(TABLE_COUNT);
        for name in TABLE_NAMES {
            match opener.open_database::<Bytes, Bytes>(rtxn, Some(name))? {
                Some(db) => v.push(db),
                None => return Ok(heed::CommitOrAbort::Abort(())),
            }
        }
        let arr: [Database<'_, Bytes, Bytes>; TABLE_COUNT] = v
            .try_into()
            .map_err(|_| StoreError::Corrupt("table list"))?;
        Ok(heed::CommitOrAbort::Commit(arr))
    })?;
    Ok(match arr {
        heed::CommitOrAbort::Commit(a) => Some(Tables::from_array(a)),
        heed::CommitOrAbort::Abort(()) => None,
    })
}

tables! {
    meta = "meta",
    objects = "objects",
    objects_key = "objects_key",
    objects_uuid = "objects_uuid",
    idx_rpsl_pk = "idx_rpsl_pk",
    idx_lookup = "idx_lookup",
    set_members = "set_members",
    ip4_range = "idx_ip4_range",
    ip4_cover = "idx_ip4_cover",
    ip6_range = "idx_ip6_range",
    ip6_cover = "idx_ip6_cover",
    asn_range = "idx_asn_range",
    asn_cover = "idx_asn_cover",
    route_origin = "idx_route_origin",
    journal = "journal",
    journal_global = "journal_global",
    status = "database_status",
    roa = "roa_object",
    suspended = "rpsl_objects_suspended",
    suspended_mntner = "idx_suspended_mntner",
    protected_name = "protected_rpsl_name",
    protected_name_idx = "idx_protected_rpsl_name",
    setting = "setting",
    auth_user = "auth_user",
    auth_permission = "auth_permission",
    auth_mntner = "auth_mntner",
    auth_api_token = "auth_api_token",
    api_token_idx = "idx_auth_api_token",
    auth_webauthn = "auth_webauthn",
    change_log = "change_log",
}

pub(crate) const META_SCHEMA_VERSION: &[u8] = b"schema_version";
pub(crate) const META_MAP_SIZE_HISTORY: &[u8] = b"map_size_history";
pub(crate) const META_NEXT_OBJECT_ID: &[u8] = b"next_object_id";
pub(crate) const META_SERIAL_GLOBAL_LAST: &[u8] = b"serial_global_last_value";
/// Set (and synced) while a bulk load without per-commit sync runs; the
/// value is the source being loaded.
pub(crate) const META_LOAD_INCOMPLETE: &[u8] = b"load_incomplete";

const GIB: usize = 1 << 30;
const MIB: usize = 1 << 20;

/// How a store is opened.
#[derive(Debug, Clone)]
pub struct StoreOptions {
    /// The directory holding `data.mdb` and `lock.mdb`. Created if missing.
    pub path: PathBuf,
    /// Initial map size for a new environment. Grown automatically.
    pub initial_map_size: usize,
    /// Open read-only: no writer thread, writes are refused.
    pub read_only: bool,
    /// Bulk-load mode: commits do not sync (`MDB_NOSYNC|MDB_NOMETASYNC`).
    /// Bracket the load with [`crate::Store::begin_bulk_load`] and
    /// [`crate::Store::finish_bulk_load`], which sync and keep a durable
    /// "load incomplete" marker so an interrupted load is never opened as
    /// a complete store.
    pub bulk_load: bool,
}

impl StoreOptions {
    /// Defaults for a store at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        StoreOptions {
            path: path.into(),
            initial_map_size: GIB,
            read_only: false,
            bulk_load: false,
        }
    }
}

/// One migration step between schema versions. Runs in the same write
/// transaction as the version bump, so a failed migration leaves the store
/// untouched.
pub(crate) struct Migration {
    pub(crate) from: u32,
    pub(crate) to: u32,
    pub(crate) run: fn(&Env<WithoutTls>, &mut RwTxn<'_>, &Tables) -> Result<()>,
}

/// The migration chain. Empty while there is only version 1.
pub(crate) const MIGRATIONS: &[Migration] = &[];

/// Readers register here so the writer can resize the map, which LMDB
/// only allows while no transaction is open in this process.
#[derive(Debug, Default)]
pub(crate) struct ReaderGate {
    state: Mutex<GateState>,
    cv: Condvar,
}

#[derive(Debug, Default)]
struct GateState {
    readers: usize,
    resizing: bool,
}

impl ReaderGate {
    pub(crate) fn enter(&self) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while s.resizing {
            s = self.cv.wait(s).unwrap_or_else(|e| e.into_inner());
        }
        s.readers += 1;
    }

    pub(crate) fn leave(&self) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.readers = s.readers.saturating_sub(1);
        self.cv.notify_all();
    }

    /// Run `f` with no read transaction open in this process.
    pub(crate) fn exclusive<R>(&self, f: impl FnOnce() -> R) -> R {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while s.resizing {
            s = self.cv.wait(s).unwrap_or_else(|e| e.into_inner());
        }
        s.resizing = true;
        while s.readers > 0 {
            s = self.cv.wait(s).unwrap_or_else(|e| e.into_inner());
        }
        drop(s);
        let r = f();
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.resizing = false;
        self.cv.notify_all();
        r
    }
}

/// The opened environment, shared by the writer and every reader.
pub(crate) struct Inner {
    pub(crate) env: Env<WithoutTls>,
    pub(crate) tables: Tables,
    pub(crate) gate: ReaderGate,
    pub(crate) read_only: bool,
    pub(crate) path: PathBuf,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("path", &self.path)
            .field("read_only", &self.read_only)
            .finish_non_exhaustive()
    }
}

fn page_round(v: usize) -> usize {
    let page = 4096 * 16;
    v.div_ceil(page) * page
}

/// The size of `data.mdb` in use, from the last page number.
pub(crate) fn used_bytes(env: &Env<WithoutTls>) -> usize {
    let info = env.info();
    let page = env.unnamed_database_stat().page_size as usize;
    (info.last_page_number + 1) * page
}

/// A map size with headroom for `used` bytes: double, at least 1 GiB more.
pub(crate) fn grown_size(used: usize, current: usize) -> usize {
    page_round((used * 2).max(used + GIB).max(current + 256 * MIB))
}

/// Whether the map should grow before the next write: under a quarter, or
/// under 256 MiB, free.
pub(crate) fn needs_growth(used: usize, map: usize) -> bool {
    let free = map.saturating_sub(used);
    free < map / 4 || free < 256 * MIB
}

pub(crate) fn open(options: &StoreOptions) -> Result<Arc<Inner>> {
    let path = &options.path;
    if !options.read_only {
        std::fs::create_dir_all(path).map_err(|e| StoreError::Io(path.clone(), e))?;
    }
    let existing = std::fs::metadata(path.join("data.mdb"))
        .map(|m| m.len() as usize)
        .unwrap_or(0);
    let map_size = page_round(options.initial_map_size.max(grown_size(existing, 0)));
    let mut opts = EnvOpenOptions::new().read_txn_without_tls();
    opts.map_size(map_size)
        .max_dbs(TABLE_NAMES.len() as u32 + 8)
        .max_readers(1022);
    if options.read_only {
        // SAFETY: setting flags before open is safe; READ_ONLY only stops
        // this handle from writing.
        unsafe {
            opts.flags(heed::EnvFlags::READ_ONLY);
        }
    } else if options.bulk_load {
        // SAFETY: as above. NO_SYNC|NO_META_SYNC only defer durability;
        // the bulk load protocol syncs explicitly and guards the gap with
        // the load-incomplete marker.
        unsafe {
            opts.flags(heed::EnvFlags::NO_SYNC | heed::EnvFlags::NO_META_SYNC);
        }
    }
    // SAFETY: heed requires that the environment is not opened twice in the
    // same process at the same time with different options and that the
    // files are not modified other than through LMDB. The store is the only
    // code opening this path, once per `Store`, and other processes use
    // LMDB's own locking.
    let env = unsafe { opts.open(path) }.map_err(|e| StoreError::open(path, e))?;

    let tables = if options.read_only {
        let tables = open_tables(&env)?.ok_or_else(|| StoreError::NotInitialised(path.clone()))?;
        let rtxn = env.read_txn()?;
        let version = read_schema_version(&rtxn, &tables)?;
        let incomplete = load_incomplete(&rtxn, &tables)?;
        drop(rtxn);
        check_version(version)?;
        if let Some(source) = incomplete {
            return Err(StoreError::LoadIncomplete {
                path: path.clone(),
                load_source: source,
            });
        }
        tables
    } else {
        let tables = create_tables(&env)?;
        let mut wtxn = env.write_txn()?;
        if let Some(source) = load_incomplete(&wtxn, &tables)? {
            wtxn.abort();
            return Err(StoreError::LoadIncomplete {
                path: path.clone(),
                load_source: source,
            });
        }
        match read_schema_version(&wtxn, &tables)? {
            None => {
                tables.meta.put(
                    &mut wtxn,
                    META_SCHEMA_VERSION,
                    &SCHEMA_VERSION.to_be_bytes(),
                )?;
            }
            Some(v) if v > SCHEMA_VERSION => {
                return Err(StoreError::SchemaTooNew {
                    found: v,
                    supported: SCHEMA_VERSION,
                });
            }
            Some(v) => migrate(&env, &mut wtxn, &tables, v)?,
        }
        record_map_size(&mut wtxn, &tables, map_size)?;
        wtxn.commit()?;
        tables
    };

    Ok(Arc::new(Inner {
        env,
        tables,
        gate: ReaderGate::default(),
        read_only: options.read_only,
        path: path.clone(),
    }))
}

fn check_version(version: Option<u32>) -> Result<()> {
    match version {
        Some(v) if v == SCHEMA_VERSION => Ok(()),
        Some(v) if v > SCHEMA_VERSION => Err(StoreError::SchemaTooNew {
            found: v,
            supported: SCHEMA_VERSION,
        }),
        Some(v) => Err(StoreError::SchemaTooOld {
            found: v,
            supported: SCHEMA_VERSION,
        }),
        None => Err(StoreError::SchemaTooOld {
            found: 0,
            supported: SCHEMA_VERSION,
        }),
    }
}

pub(crate) fn load_incomplete(rtxn: &RoTxn<'_>, tables: &Tables) -> Result<Option<String>> {
    Ok(tables
        .meta
        .get(rtxn, META_LOAD_INCOMPLETE)?
        .map(|b| String::from_utf8_lossy(b).into_owned()))
}

pub(crate) fn read_schema_version(rtxn: &RoTxn<'_>, tables: &Tables) -> Result<Option<u32>> {
    Ok(match tables.meta.get(rtxn, META_SCHEMA_VERSION)? {
        Some(b) => Some(u32::from_be_bytes(
            b.try_into()
                .map_err(|_| StoreError::Corrupt("schema_version"))?,
        )),
        None => None,
    })
}

/// Bring the store from `from` to [`SCHEMA_VERSION`].
pub(crate) fn migrate(
    env: &Env<WithoutTls>,
    wtxn: &mut RwTxn<'_>,
    tables: &Tables,
    mut from: u32,
) -> Result<()> {
    migrate_with(env, wtxn, tables, &mut from, MIGRATIONS, SCHEMA_VERSION)
}

pub(crate) fn migrate_with(
    env: &Env<WithoutTls>,
    wtxn: &mut RwTxn<'_>,
    tables: &Tables,
    from: &mut u32,
    migrations: &[Migration],
    target: u32,
) -> Result<()> {
    while *from < target {
        let step = migrations
            .iter()
            .find(|m| m.from == *from)
            .ok_or(StoreError::NoMigration {
                from: *from,
                to: target,
            })?;
        tracing::info!("{}", messages::migrating(step.from, step.to));
        (step.run)(env, wtxn, tables)?;
        *from = step.to;
        tables
            .meta
            .put(wtxn, META_SCHEMA_VERSION, &from.to_be_bytes())?;
    }
    Ok(())
}

/// Append a map size to the history in `meta`, if it changed.
pub(crate) fn record_map_size(wtxn: &mut RwTxn<'_>, tables: &Tables, size: usize) -> Result<()> {
    let mut history: Vec<(String, u64)> = match tables.meta.get(wtxn, META_MAP_SIZE_HISTORY)? {
        Some(b) => serde_json::from_slice(b).unwrap_or_default(),
        None => Vec::new(),
    };
    if history.last().map(|(_, s)| *s) != Some(size as u64) {
        history.push((crate::model::Timestamp::now().to_string(), size as u64));
        let bytes = serde_json::to_vec(&history).map_err(|_| StoreError::Corrupt("meta"))?;
        tables.meta.put(wtxn, META_MAP_SIZE_HISTORY, &bytes)?;
    }
    Ok(())
}

/// Grow the map to `new_size`, waiting for this process's readers.
pub(crate) fn resize(inner: &Inner, new_size: usize) -> Result<()> {
    let new_size = page_round(new_size);
    inner.gate.exclusive(|| {
        tracing::info!("{}", messages::map_resized(new_size));
        // SAFETY: the reader gate guarantees no read transaction of this
        // process is open, and the writer thread (the only one that opens
        // write transactions) is the caller and holds none.
        unsafe { inner.env.resize(new_size) }
    })?;
    Ok(())
}

/// The path of the data file of a store directory.
pub fn data_file(path: &Path) -> PathBuf {
    path.join("data.mdb")
}

/// Overwrite the schema version of a store on disk. Tests only.
#[doc(hidden)]
pub fn set_schema_version_for_tests(path: &Path, version: u32) -> Result<()> {
    let mut opts = EnvOpenOptions::new().read_txn_without_tls();
    opts.map_size(64 << 20)
        .max_dbs(TABLE_NAMES.len() as u32 + 8);
    // SAFETY: as in `open`; the caller has dropped every other handle.
    let env = unsafe { opts.open(path) }.map_err(|e| StoreError::open(path, e))?;
    let tables = create_tables(&env)?;
    let mut wtxn = env.write_txn()?;
    tables
        .meta
        .put(&mut wtxn, META_SCHEMA_VERSION, &version.to_be_bytes())?;
    wtxn.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bump(_: &Env<WithoutTls>, wtxn: &mut RwTxn<'_>, t: &Tables) -> Result<()> {
        t.meta.put(wtxn, b"migrated", b"yes")?;
        Ok(())
    }

    #[test]
    fn migrations_run_in_order_and_record_the_version() {
        let dir =
            std::env::temp_dir().join(format!("irrd-ng-store-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut o = StoreOptions::new(&dir);
        o.initial_map_size = 16 << 20;
        let inner = open(&o).expect("open");
        let steps = [Migration {
            from: 1,
            to: 2,
            run: bump,
        }];
        let mut wtxn = inner.env.write_txn().expect("txn");
        let mut v = 1;
        migrate_with(&inner.env, &mut wtxn, &inner.tables, &mut v, &steps, 2).expect("migrate");
        assert_eq!(v, 2);
        assert_eq!(
            read_schema_version(&wtxn, &inner.tables).expect("v"),
            Some(2)
        );
        assert_eq!(
            inner.tables.meta.get(&wtxn, b"migrated").expect("get"),
            Some(&b"yes"[..])
        );
        let mut v = 2;
        let e =
            migrate_with(&inner.env, &mut wtxn, &inner.tables, &mut v, &steps, 3).expect_err("gap");
        assert!(matches!(e, StoreError::NoMigration { from: 2, to: 3 }));
        wtxn.abort();
        drop(inner);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
