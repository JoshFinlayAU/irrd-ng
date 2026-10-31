//! Reads shared by read and write transactions.

use heed::RoTxn;

use crate::env::{META_SERIAL_GLOBAL_LAST, Tables};
use crate::error::{Result, StoreError};
use crate::index::object_key;
use crate::keys::{id_bytes, push_str, serial_bytes};
use crate::model::{DatabaseStatus, Uuid};
use crate::records::{JournalEntryRef, RpslObjectRef, decode};

pub(crate) fn object_by_id<'t>(
    t: &Tables,
    txn: &'t RoTxn<'_>,
    id: u64,
) -> Result<Option<RpslObjectRef<'t>>> {
    match t.objects.get(txn, &id_bytes(id))? {
        Some(b) => Ok(Some(decode(b)?)),
        None => Ok(None),
    }
}

pub(crate) fn id_by_key(
    t: &Tables,
    txn: &RoTxn<'_>,
    source: &str,
    class: &str,
    rpsl_pk: &str,
) -> Result<Option<u64>> {
    match t
        .objects_key
        .get(txn, &object_key(source, class, rpsl_pk))?
    {
        Some(b) => Ok(Some(u64::from_be_bytes(
            b.try_into().map_err(|_| StoreError::Corrupt("object id"))?,
        ))),
        None => Ok(None),
    }
}

pub(crate) fn id_by_uuid(t: &Tables, txn: &RoTxn<'_>, uuid: &Uuid) -> Result<Option<u64>> {
    match t.objects_uuid.get(txn, uuid.as_bytes())? {
        Some(b) => Ok(Some(u64::from_be_bytes(
            b.try_into().map_err(|_| StoreError::Corrupt("object id"))?,
        ))),
        None => Ok(None),
    }
}

pub(crate) fn status(t: &Tables, txn: &RoTxn<'_>, source: &str) -> Result<Option<DatabaseStatus>> {
    match t.status.get(txn, source.as_bytes())? {
        Some(b) => Ok(Some(decode(b)?)),
        None => Ok(None),
    }
}

pub(crate) fn journal_key(source: &str, serial: i64) -> Vec<u8> {
    let mut k = Vec::with_capacity(source.len() + 10);
    push_str(&mut k, source.as_bytes());
    k.extend_from_slice(&serial_bytes(serial));
    k
}

pub(crate) fn journal_entry<'t>(
    t: &Tables,
    txn: &'t RoTxn<'_>,
    source: &str,
    serial: i64,
) -> Result<Option<JournalEntryRef<'t>>> {
    match t.journal.get(txn, &journal_key(source, serial))? {
        Some(b) => Ok(Some(decode(b)?)),
        None => Ok(None),
    }
}

/// Lowest and highest `serial_nrtm` in the journal of a source.
pub(crate) fn journal_serial_bounds(
    t: &Tables,
    txn: &RoTxn<'_>,
    source: &str,
) -> Result<Option<(i64, i64)>> {
    let mut p = Vec::new();
    push_str(&mut p, source.as_bytes());
    let first = t.journal.prefix_iter(txn, &p)?.next().transpose()?;
    let Some((fk, _)) = first else {
        return Ok(None);
    };
    let last = t.journal.rev_prefix_iter(txn, &p)?.next().transpose()?;
    let lk = last.map(|(k, _)| k).unwrap_or(fk);
    let s = |k: &[u8]| {
        crate::keys::serial_from(&k[p.len()..]).ok_or(StoreError::Corrupt("journal key"))
    };
    Ok(Some((s(fk)?, s(lk)?)))
}

pub(crate) fn serial_global_last(t: &Tables, txn: &RoTxn<'_>) -> Result<i64> {
    Ok(match t.meta.get(txn, META_SERIAL_GLOBAL_LAST)? {
        Some(b) => crate::keys::serial_from(b).ok_or(StoreError::Corrupt("meta"))?,
        None => 0,
    })
}
