//! The replication log: irrd-ng's counterpart of the PostgreSQL write-ahead
//! log that v4 standbys stream from their active.
//!
//! When an active has enabled it ([`crate::Store::enable_replication_log`]),
//! every write transaction that changes the store appends one [`Entry`] to
//! the `replication_log` table, in the same LMDB transaction: the row-level
//! changes it made to every table (objects, indexes, journal, status, ROAs,
//! suspension, settings, the web UI tables and the keyring), in order. The
//! log covers writes from every process, since the command line tools write
//! through the same code. A standby that applies the entries in sequence
//! order ends up with the same rows, byte for byte, as the active.
//!
//! Changes are captured below [`crate::WriteTx`], in the table wrapper
//! ([`crate::env::Table`]), into a per-thread frame opened by the writer
//! around each job, so no write path can bypass the log. A transaction
//! that writes more than [`MAX_ENTRY_BYTES`], or any write in bulk-load
//! mode (the v4 import, `irrd_load_database`), logs a [`Body::Resync`]
//! instead of its rows: a standby that reaches one reloads from a snapshot.
//!
//! Some `meta` keys are local to one store and never replicated: the
//! schema version, the map size history, bulk load markers and this
//! module's own `repl:` keys ([`is_local_meta_key`]).

use std::cell::RefCell;
use std::io::{Read, Write};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::env::{TABLE_NAMES, Tables};
use crate::error::{Result, StoreError};

/// The log id of an active store: set while logging is enabled.
pub(crate) const META_ID: &[u8] = b"repl:id";
/// The sequence number of the newest entry ever written.
pub(crate) const META_LAST_SEQ: &[u8] = b"repl:last_seq";
/// On a standby: the log id it follows.
pub(crate) const META_FOLLOW_ID: &[u8] = b"repl:follow_id";
/// On a standby: the last sequence number applied.
pub(crate) const META_FOLLOW_SEQ: &[u8] = b"repl:follow_seq";

/// Larger transactions log a resync instead of their rows.
pub const MAX_ENTRY_BYTES: usize = 64 << 20;

const fn table_id(name: &str) -> u8 {
    let mut i = 0;
    while i < TABLE_NAMES.len() {
        let a = TABLE_NAMES[i].as_bytes();
        let b = name.as_bytes();
        if a.len() == b.len() {
            let mut j = 0;
            let mut same = true;
            while j < a.len() {
                if a[j] != b[j] {
                    same = false;
                }
                j += 1;
            }
            if same {
                return i as u8;
            }
        }
        i += 1;
    }
    panic!("unknown table");
}

/// The wire id of `meta`.
pub(crate) const META_TABLE: u8 = table_id("meta");
/// The wire id of the log itself, which is never replicated.
pub(crate) const REPLOG_TABLE: u8 = table_id("replication_log");

/// Whether a `meta` key belongs to this store alone.
pub fn is_local_meta_key(key: &[u8]) -> bool {
    key.starts_with(b"repl:")
        || key.starts_with(crate::env::META_LOAD_INCOMPLETE)
        || key == crate::env::META_MAP_SIZE_HISTORY
        || key == crate::env::META_SCHEMA_VERSION
}

/// Whether a row of table `table` is replicated.
pub(crate) fn is_replicated(table: u8, key: &[u8]) -> bool {
    table != REPLOG_TABLE && !(table == META_TABLE && is_local_meta_key(key))
}

/// One row-level change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    /// Insert or overwrite a row.
    Put {
        /// The table, by its position in [`TABLE_NAMES`].
        table: u8,
        /// The key.
        key: Vec<u8>,
        /// The value.
        value: Vec<u8>,
    },
    /// Delete a row.
    Delete {
        /// The table.
        table: u8,
        /// The key.
        key: Vec<u8>,
    },
    /// Delete every row of a table.
    Clear {
        /// The table.
        table: u8,
    },
}

/// What one logged transaction did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Body {
    /// These changes, in order.
    Ops(Vec<Op>),
    /// Too much to log row by row: followers reload from a snapshot.
    Resync,
}

/// One log entry: one committed transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Commit time, microseconds since the epoch.
    pub micros: i64,
    /// The changes.
    pub body: Body,
}

impl Entry {
    /// Decode a stored entry.
    pub fn decode(bytes: &[u8]) -> Result<Entry> {
        Ok(postcard::from_bytes(bytes)?)
    }

    /// Encode for storage.
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(postcard::to_stdvec(self)?)
    }

    /// Whether the stored entry is a resync marker, without decoding the
    /// changes.
    pub fn is_resync(bytes: &[u8]) -> Result<bool> {
        let (_, rest): (i64, &[u8]) = postcard::take_from_bytes(bytes)?;
        let (variant, _): (u32, &[u8]) = postcard::take_from_bytes(rest)?;
        Ok(variant == 1)
    }

    /// The commit time of a stored entry, without decoding the changes.
    pub fn micros_of(bytes: &[u8]) -> Result<i64> {
        Ok(postcard::take_from_bytes::<i64>(bytes)?.0)
    }
}

// ---------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------

#[derive(Default)]
struct Frame {
    ops: Vec<Op>,
    bytes: usize,
    count: u64,
    overflow: bool,
}

thread_local! {
    /// One frame per open (nested) write job on this thread. Writes only
    /// happen on a store's writer thread, inside a job.
    static FRAMES: RefCell<Vec<Frame>> = const { RefCell::new(Vec::new()) };
}

fn with_top(f: impl FnOnce(&mut Frame)) {
    FRAMES.with(|frames| {
        if let Some(top) = frames.borrow_mut().last_mut() {
            f(top);
        }
    });
}

fn push(frame: &mut Frame, op: Op, size: usize) {
    frame.count += 1;
    if frame.overflow {
        return;
    }
    frame.bytes += size + 16;
    if frame.bytes > MAX_ENTRY_BYTES {
        frame.overflow = true;
        frame.ops = Vec::new();
    } else {
        frame.ops.push(op);
    }
}

pub(crate) fn record_put(table: u8, key: &[u8], value: &[u8]) {
    if !is_replicated(table, key) {
        return;
    }
    with_top(|f| {
        let size = key.len() + value.len();
        let op = if f.overflow {
            Op::Clear { table }
        } else {
            Op::Put {
                table,
                key: key.to_vec(),
                value: value.to_vec(),
            }
        };
        push(f, op, size);
    });
}

pub(crate) fn record_delete(table: u8, key: &[u8]) {
    if !is_replicated(table, key) {
        return;
    }
    with_top(|f| {
        let op = if f.overflow {
            Op::Clear { table }
        } else {
            Op::Delete {
                table,
                key: key.to_vec(),
            }
        };
        push(f, op, key.len());
    });
}

pub(crate) fn record_clear(table: u8) {
    if table == REPLOG_TABLE {
        return;
    }
    // Clearing `meta` would include local keys; nothing clears it today.
    with_top(|f| push(f, Op::Clear { table }, 0));
}

/// Capture for one write job: open while the job runs, then
/// [`Capture::commit`] writes the entry into the job's transaction.
/// Dropping it without committing discards what was captured.
pub(crate) struct Capture {
    open: bool,
}

/// Start capturing, if the store's log is enabled. In bulk-load mode the
/// rows are not kept: the entry will be a resync.
pub(crate) fn begin(enabled: bool, bulk_load: bool) -> Capture {
    if enabled {
        FRAMES.with(|frames| {
            frames.borrow_mut().push(Frame {
                overflow: bulk_load,
                ..Frame::default()
            });
        });
    }
    Capture { open: enabled }
}

impl Capture {
    /// Append what was captured to the log, in `txn`.
    pub(crate) fn commit(mut self, txn: &mut RwTxn<'_>, t: &Tables) -> Result<()> {
        if !self.open {
            return Ok(());
        }
        self.open = false;
        let frame = FRAMES
            .with(|frames| frames.borrow_mut().pop())
            .unwrap_or_default();
        if frame.count == 0 {
            return Ok(());
        }
        let body = if frame.overflow {
            Body::Resync
        } else {
            Body::Ops(frame.ops)
        };
        append(txn, t, body)
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if self.open {
            FRAMES.with(|frames| {
                frames.borrow_mut().pop();
            });
        }
    }
}

fn read_u64(bytes: Option<&[u8]>) -> Result<Option<u64>> {
    bytes
        .map(|b| {
            b.try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| StoreError::Corrupt("replication sequence"))
        })
        .transpose()
}

/// Whether the store's log is enabled.
pub(crate) fn enabled(txn: &RoTxn<'_>, t: &Tables) -> Result<bool> {
    Ok(t.meta.get(txn, META_ID)?.is_some())
}

fn append(txn: &mut RwTxn<'_>, t: &Tables, body: Body) -> Result<()> {
    let last = read_u64(t.meta.get(txn, META_LAST_SEQ)?)?.unwrap_or(0);
    let seq = last + 1;
    let entry = Entry {
        micros: crate::model::Timestamp::now().0,
        body,
    };
    t.replog
        .raw()
        .put(txn, &seq.to_be_bytes(), &entry.encode()?)?;
    t.meta.raw().put(txn, META_LAST_SEQ, &seq.to_be_bytes())?;
    Ok(())
}

// ---------------------------------------------------------------------
// The active's side
// ---------------------------------------------------------------------

/// A callback receiving one replicated row: table id, key, value.
pub type RowSink<'a> = &'a mut dyn FnMut(u8, &[u8], &[u8]) -> Result<()>;

/// Stored log entries: (sequence number, encoded [`Entry`]).
pub type StoredEntries = Vec<(u64, Vec<u8>)>;

/// One spooled snapshot row: table id, key, value.
pub type SpoolRow = (u8, Vec<u8>, Vec<u8>);

/// The replication state of a store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicationState {
    /// The log id, while logging is enabled.
    pub id: Option<String>,
    /// The oldest entry still kept.
    pub first_seq: Option<u64>,
    /// The newest entry ever written (0 if none).
    pub last_seq: u64,
    /// On a standby: the log id it follows and the last entry applied.
    pub follow: Option<(String, u64)>,
}

pub(crate) fn state(txn: &RoTxn<'_>, t: &Tables) -> Result<ReplicationState> {
    let id = t
        .meta
        .get(txn, META_ID)?
        .map(|b| String::from_utf8_lossy(b).into_owned());
    let first_seq = match t.replog.first(txn)? {
        Some((k, _)) => read_u64(Some(k))?,
        None => None,
    };
    let last_seq = read_u64(t.meta.get(txn, META_LAST_SEQ)?)?.unwrap_or(0);
    let follow = match (
        t.meta.get(txn, META_FOLLOW_ID)?,
        read_u64(t.meta.get(txn, META_FOLLOW_SEQ)?)?,
    ) {
        (Some(id), Some(seq)) => Some((String::from_utf8_lossy(id).into_owned(), seq)),
        _ => None,
    };
    Ok(ReplicationState {
        id,
        first_seq,
        last_seq,
        follow,
    })
}

/// Entries after `after`, as stored, up to about `max_bytes`.
pub(crate) fn entries_after(
    txn: &RoTxn<'_>,
    t: &Tables,
    after: u64,
    max_bytes: usize,
) -> Result<StoredEntries> {
    let mut out = Vec::new();
    let mut size = 0;
    let from = (after + 1).to_be_bytes();
    let bounds = (
        std::ops::Bound::Included(&from[..]),
        std::ops::Bound::Unbounded,
    );
    for item in t.replog.range(txn, &bounds)? {
        let (k, v) = item?;
        let seq = read_u64(Some(k))?.unwrap_or(0);
        if !out.is_empty() && size + v.len() > max_bytes {
            break;
        }
        size += v.len();
        out.push((seq, v.to_vec()));
    }
    Ok(out)
}

/// Every replicated row, table by table in key order, to `row`.
pub(crate) fn snapshot(txn: &RoTxn<'_>, t: &Tables, row: RowSink<'_>) -> Result<()> {
    for (_, table) in t.named() {
        if table.id == REPLOG_TABLE {
            continue;
        }
        for item in table.iter(txn)? {
            let (k, v) = item?;
            if is_replicated(table.id, k) {
                row(table.id, k, v)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn enable(txn: &mut RwTxn<'_>, t: &Tables) -> Result<String> {
    if let Some(id) = t.meta.get(txn, META_ID)? {
        return Ok(String::from_utf8_lossy(id).into_owned());
    }
    let id = crate::model::Uuid::new_v4().to_string();
    t.meta.raw().put(txn, META_ID, id.as_bytes())?;
    Ok(id)
}

pub(crate) fn disable(txn: &mut RwTxn<'_>, t: &Tables) -> Result<bool> {
    let was = t.meta.raw().delete(txn, META_ID)?;
    t.replog.raw().clear(txn)?;
    Ok(was)
}

/// Delete entries committed before `before_micros`, keeping at least the
/// newest one. Returns how many went.
pub(crate) fn trim(txn: &mut RwTxn<'_>, t: &Tables, before_micros: i64) -> Result<u64> {
    let last = read_u64(t.meta.get(txn, META_LAST_SEQ)?)?.unwrap_or(0);
    let mut doomed = Vec::new();
    for item in t.replog.iter(txn)? {
        let (k, v) = item?;
        let seq = read_u64(Some(k))?.unwrap_or(0);
        if seq >= last || Entry::micros_of(v)? >= before_micros {
            break;
        }
        doomed.push(seq);
    }
    for seq in &doomed {
        t.replog.raw().delete(txn, &seq.to_be_bytes())?;
    }
    Ok(doomed.len() as u64)
}

// ---------------------------------------------------------------------
// The standby's side
// ---------------------------------------------------------------------

fn check_table(table: u8) -> Result<()> {
    if usize::from(table) >= TABLE_NAMES.len() || table == REPLOG_TABLE {
        return Err(StoreError::Replication(format!(
            "entry names table {table}, which is not replicated"
        )));
    }
    Ok(())
}

fn table_by_id(t: &Tables, table: u8) -> Result<crate::env::Table> {
    check_table(table)?;
    t.named()
        .into_iter()
        .map(|(_, tb)| tb)
        .find(|tb| tb.id == table)
        .ok_or(StoreError::Corrupt("table id"))
}

fn set_follow(txn: &mut RwTxn<'_>, t: &Tables, id: &str, seq: u64) -> Result<()> {
    t.meta.raw().put(txn, META_FOLLOW_ID, id.as_bytes())?;
    t.meta.raw().put(txn, META_FOLLOW_SEQ, &seq.to_be_bytes())?;
    Ok(())
}

/// Apply entries from the log `id`, which must continue from what was
/// applied last.
pub(crate) fn apply_entries(
    txn: &mut RwTxn<'_>,
    t: &Tables,
    id: &str,
    entries: &[(u64, Vec<u8>)],
) -> Result<u64> {
    let st = state(txn, t)?;
    let mut expect = match &st.follow {
        Some((fid, seq)) if fid == id => seq + 1,
        _ => {
            return Err(StoreError::Replication(
                "entries for a log this store has no snapshot of".into(),
            ));
        }
    };
    for (seq, bytes) in entries {
        if *seq != expect {
            return Err(StoreError::Replication(format!(
                "entry {seq} does not follow {}",
                expect - 1
            )));
        }
        let entry = Entry::decode(bytes)?;
        let Body::Ops(ops) = entry.body else {
            return Err(StoreError::Replication(format!(
                "entry {seq} needs a snapshot"
            )));
        };
        for op in ops {
            match op {
                Op::Put { table, key, value } => {
                    if is_replicated(table, &key) {
                        table_by_id(t, table)?.put(txn, &key, &value)?;
                    }
                }
                Op::Delete { table, key } => {
                    if is_replicated(table, &key) {
                        table_by_id(t, table)?.delete(txn, &key)?;
                    }
                }
                Op::Clear { table } => clear_replicated(txn, t, table)?,
            }
        }
        expect += 1;
    }
    let applied = expect - 1;
    set_follow(txn, t, id, applied)?;
    Ok(applied)
}

fn clear_replicated(txn: &mut RwTxn<'_>, t: &Tables, table: u8) -> Result<()> {
    let tb = table_by_id(t, table)?;
    if table != META_TABLE {
        return Ok(tb.clear(txn)?);
    }
    let mut keys = Vec::new();
    for item in tb.iter(txn)? {
        let (k, _) = item?;
        if !is_local_meta_key(k) {
            keys.push(k.to_vec());
        }
    }
    for k in keys {
        tb.delete(txn, &k)?;
    }
    Ok(())
}

/// Replace every replicated row with the rows of a snapshot spool file
/// ([`write_spool_row`]) taken from log `id` at `seq`.
pub(crate) fn apply_snapshot(
    txn: &mut RwTxn<'_>,
    t: &Tables,
    id: &str,
    seq: u64,
    spool: &std::path::Path,
) -> Result<u64> {
    for (_, tb) in t.named() {
        if tb.id != REPLOG_TABLE {
            clear_replicated(txn, t, tb.id)?;
        }
    }
    let file = std::fs::File::open(spool).map_err(|e| StoreError::Io(spool.to_path_buf(), e))?;
    let mut r = std::io::BufReader::with_capacity(1 << 20, file);
    let mut rows = 0;
    while let Some((table, key, value)) =
        read_spool_row(&mut r).map_err(|e| StoreError::Io(spool.to_path_buf(), e))?
    {
        if is_replicated(table, &key) {
            table_by_id(t, table)?.put(txn, &key, &value)?;
            rows += 1;
        }
    }
    set_follow(txn, t, id, seq)?;
    Ok(rows)
}

/// Append one snapshot row to a spool: the table id, then the key and the
/// value, each with a 4-byte big-endian length. The same encoding carries
/// snapshot rows on the wire.
pub fn write_spool_row(
    w: &mut impl Write,
    table: u8,
    key: &[u8],
    value: &[u8],
) -> std::io::Result<()> {
    let len = |n: usize| {
        u32::try_from(n)
            .map(u32::to_be_bytes)
            .map_err(|_| std::io::Error::other("row too large"))
    };
    w.write_all(&[table])?;
    w.write_all(&len(key.len())?)?;
    w.write_all(key)?;
    w.write_all(&len(value.len())?)?;
    w.write_all(value)
}

/// Read one row written by [`write_spool_row`]; `None` at the end.
pub fn read_spool_row(r: &mut impl Read) -> std::io::Result<Option<SpoolRow>> {
    let mut table = [0u8; 1];
    match r.read_exact(&mut table) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let read_vec = |r: &mut dyn Read| -> std::io::Result<Vec<u8>> {
        let mut len = [0u8; 4];
        r.read_exact(&mut len)?;
        let mut v = vec![0u8; u32::from_be_bytes(len) as usize];
        r.read_exact(&mut v)?;
        Ok(v)
    };
    let key = read_vec(r)?;
    let value = read_vec(r)?;
    Ok(Some((table[0], key, value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_local_keys() {
        assert_eq!(TABLE_NAMES[META_TABLE as usize], "meta");
        assert_eq!(TABLE_NAMES[REPLOG_TABLE as usize], "replication_log");
        assert!(is_local_meta_key(b"repl:id"));
        assert!(is_local_meta_key(b"schema_version"));
        assert!(is_local_meta_key(b"load_incomplete_source:RADB"));
        assert!(!is_local_meta_key(b"next_object_id"));
        assert!(!is_replicated(REPLOG_TABLE, b"x"));
        assert!(is_replicated(META_TABLE, b"serial_global_last_value"));
    }

    #[test]
    fn entry_header_without_decoding() {
        let e = Entry {
            micros: 1_793_408_028_927_123,
            body: Body::Ops(vec![Op::Put {
                table: 3,
                key: b"k".to_vec(),
                value: b"v".to_vec(),
            }]),
        };
        let b = e.encode().expect("encode");
        assert_eq!(Entry::micros_of(&b).expect("t"), e.micros);
        assert!(!Entry::is_resync(&b).expect("r"));
        assert_eq!(Entry::decode(&b).expect("d"), e);
        let r = Entry {
            micros: 5,
            body: Body::Resync,
        }
        .encode()
        .expect("encode");
        assert!(Entry::is_resync(&r).expect("r"));
    }

    #[test]
    fn spool_rows_round_trip() {
        let mut buf = Vec::new();
        write_spool_row(&mut buf, 1, b"key", b"value").expect("w");
        write_spool_row(&mut buf, 2, b"", b"").expect("w");
        let mut r = &buf[..];
        assert_eq!(
            read_spool_row(&mut r).expect("r"),
            Some((1, b"key".to_vec(), b"value".to_vec()))
        );
        assert_eq!(
            read_spool_row(&mut r).expect("r"),
            Some((2, vec![], vec![]))
        );
        assert_eq!(read_spool_row(&mut r).expect("r"), None);
    }
}
