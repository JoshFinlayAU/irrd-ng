//! Read access: [`ReadTx`] owns an LMDB read transaction, [`ReadView`] is
//! the query surface over any transaction (read or write).
//!
//! Records borrow from the memory map, so a [`RpslObjectRef`] read through
//! a view lives as long as the transaction. Keep read transactions short in
//! long-running tasks (NRTM serving, the event stream): an open read
//! transaction stops LMDB from reusing pages freed after it started.

use std::sync::Arc;

use heed::{RoTxn, WithoutTls};

use crate::env::{Inner, Tables};
use crate::error::{Result, StoreError};
use crate::index::{self, OriginRoute, Space};
use crate::keys::{push_str, serial_bytes};
use crate::model::{
    AuthApiTokenRow, AuthMntnerRow, AuthPermissionRow, AuthUserRow, AuthWebAuthnRow, ChangeLogRow,
    DatabaseStatus, IpPrefix, ProtectedNameRow, RoaRow, SettingRow, SuspendedObjectRow, Uuid,
};
use crate::query;
use crate::records::{JournalEntryRef, RoaValue, RpslObjectRef, SetMembers, decode};

/// An internal object id: stable for the life of a row, not exposed by v4.
pub type ObjectId = u64;

/// An owned read transaction.
pub struct ReadTx {
    inner: Arc<Inner>,
    txn: Option<RoTxn<'static, WithoutTls>>,
}

impl std::fmt::Debug for ReadTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadTx").finish_non_exhaustive()
    }
}

impl ReadTx {
    pub(crate) fn begin(inner: Arc<Inner>) -> Result<Self> {
        inner.gate.enter();
        match inner.env.clone().static_read_txn() {
            Ok(txn) => Ok(ReadTx {
                inner,
                txn: Some(txn),
            }),
            Err(e) => {
                inner.gate.leave();
                Err(e.into())
            }
        }
    }

    /// Run `f` on the raw transaction and tables.
    pub(crate) fn with_txn<R>(
        &self,
        f: impl FnOnce(&RoTxn<'_>, &Tables) -> Result<R>,
    ) -> Result<R> {
        let txn: &RoTxn<'_> = self.txn.as_deref().unwrap_or_else(|| unreachable!());
        f(txn, &self.inner.tables)
    }

    /// The query surface.
    pub fn view(&self) -> ReadView<'_> {
        // The transaction is only taken out in Drop.
        let txn: &RoTxn<'_> = self.txn.as_deref().unwrap_or_else(|| unreachable!());
        ReadView::new(self.inner.tables, txn)
    }
}

impl Drop for ReadTx {
    fn drop(&mut self) {
        drop(self.txn.take());
        self.inner.gate.leave();
    }
}

/// Queries over one transaction.
#[derive(Clone, Copy)]
pub struct ReadView<'a> {
    t: Tables,
    txn: &'a RoTxn<'a>,
}

impl std::fmt::Debug for ReadView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadView").finish_non_exhaustive()
    }
}

fn id_of(v: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        v.try_into().map_err(|_| StoreError::Corrupt("object id"))?,
    ))
}

impl<'a> ReadView<'a> {
    pub(crate) fn new(t: Tables, txn: &'a RoTxn<'a>) -> Self {
        ReadView { t, txn }
    }

    // ---- rpsl_objects ----

    /// The object with this source, class and primary key.
    pub fn object(
        &self,
        source: &str,
        class: &str,
        rpsl_pk: &str,
    ) -> Result<Option<RpslObjectRef<'a>>> {
        match query::id_by_key(&self.t, self.txn, source, class, rpsl_pk)? {
            Some(id) => query::object_by_id(&self.t, self.txn, id),
            None => Ok(None),
        }
    }

    /// The internal id of the object with this source, class and primary
    /// key.
    pub fn object_id(&self, source: &str, class: &str, rpsl_pk: &str) -> Result<Option<ObjectId>> {
        query::id_by_key(&self.t, self.txn, source, class, rpsl_pk)
    }

    /// The object with this row UUID.
    pub fn object_by_pk(&self, pk: &Uuid) -> Result<Option<RpslObjectRef<'a>>> {
        match query::id_by_uuid(&self.t, self.txn, pk)? {
            Some(id) => query::object_by_id(&self.t, self.txn, id),
            None => Ok(None),
        }
    }

    /// The object with this internal id.
    pub fn object_by_id(&self, id: ObjectId) -> Result<Option<RpslObjectRef<'a>>> {
        query::object_by_id(&self.t, self.txn, id)
    }

    /// Objects in (source, class, rpsl_pk) byte order, optionally limited
    /// to one source and then one class.
    pub fn objects(
        &self,
        source: Option<&str>,
        class: Option<&str>,
    ) -> Result<impl Iterator<Item = Result<(ObjectId, RpslObjectRef<'a>)>> + 'a> {
        let mut p = Vec::new();
        if let Some(s) = source {
            push_str(&mut p, s.as_bytes());
            if let Some(c) = class {
                push_str(&mut p, c.as_bytes());
            }
        }
        let t = self.t;
        let txn = self.txn;
        type KvIter<'x> = Box<dyn Iterator<Item = heed::Result<(&'x [u8], &'x [u8])>> + 'x>;
        let raw: KvIter<'a> = if p.is_empty() {
            Box::new(t.objects_key.iter(txn)?)
        } else {
            Box::new(t.objects_key.prefix_iter(txn, &p)?)
        };
        Ok(raw.map(move |item| {
            let (_, v) = item?;
            let id = id_of(v)?;
            let o =
                query::object_by_id(&t, txn, id)?.ok_or(StoreError::Corrupt("missing object"))?;
            Ok((id, o))
        }))
    }

    /// Every source that has objects, in byte order. Skips from one
    /// source to the next instead of reading every key.
    pub fn object_sources(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let mut from: Vec<u8> = Vec::new();
        loop {
            // LMDB rejects an empty key, so the first look is unbounded.
            let lower = if from.is_empty() {
                std::ops::Bound::Unbounded
            } else {
                std::ops::Bound::Included(from.as_slice())
            };
            let bounds = (lower, std::ops::Bound::Unbounded);
            let Some(item) = self.t.objects_key.range(self.txn, &bounds)?.next() else {
                break;
            };
            let (k, _) = item?;
            let (source, _) = crate::keys::take_str(k).ok_or(StoreError::Corrupt("object key"))?;
            let name = String::from_utf8(source).map_err(|_| StoreError::Corrupt("object key"))?;
            // The next key after every key of this source: its terminator
            // 0x00 0x01 bumped to 0x00 0x02.
            from.clear();
            push_str(&mut from, name.as_bytes());
            if let Some(last) = from.last_mut() {
                *last = 2;
            }
            out.push(name);
        }
        Ok(out)
    }

    /// Object counts per (source, object class), from the key index alone
    /// (`RPSLDatabaseObjectStatisticsQuery`).
    pub fn object_class_counts(&self) -> Result<Vec<(String, String, u64)>> {
        let mut out: Vec<(String, String, u64)> = Vec::new();
        for item in self.t.objects_key.iter(self.txn)? {
            let (k, _) = item?;
            let (source, rest) =
                crate::keys::take_str(k).ok_or(StoreError::Corrupt("object key"))?;
            let (class, _) =
                crate::keys::take_str(rest).ok_or(StoreError::Corrupt("object key"))?;
            match out.last_mut() {
                Some(l)
                    if l.0.as_bytes() == source.as_slice()
                        && l.1.as_bytes() == class.as_slice() =>
                {
                    l.2 += 1;
                }
                _ => out.push((
                    String::from_utf8(source).map_err(|_| StoreError::Corrupt("object key"))?,
                    String::from_utf8(class).map_err(|_| StoreError::Corrupt("object key"))?,
                    1,
                )),
            }
        }
        Ok(out)
    }

    /// Number of objects.
    pub fn object_count(&self) -> Result<u64> {
        Ok(self.t.objects.len(self.txn)?)
    }

    /// Ids of objects whose `rpsl_pk` equals `rpsl_pk` (already upper-cased).
    pub fn ids_by_rpsl_pk(&self, rpsl_pk: &str) -> Result<Vec<ObjectId>> {
        index::ids_by_rpsl_pk(&self.t, self.txn, rpsl_pk)
    }

    /// `parsed_data->attr ? value` (`Some`) or `parsed_data ? attr` (`None`).
    /// `attr` must be one of [`index::LOOKUP_FIELD_NAMES`].
    pub fn ids_by_lookup(&self, attr: &str, value: Option<&str>) -> Result<Vec<ObjectId>> {
        index::ids_by_lookup(&self.t, self.txn, attr, value)
    }

    /// Forward members of every as-set or route-set named `rpsl_pk`, as
    /// (source, class, members).
    pub fn set_members(&self, rpsl_pk: &str) -> Result<Vec<(String, String, SetMembers<'a>)>> {
        index::set_members(&self.t, self.txn, rpsl_pk)
    }

    /// Objects whose range is exactly `[first, last]` in `space`, as
    /// (id, first, last).
    pub fn range_exact(
        &self,
        space: Space,
        first: u128,
        last: u128,
    ) -> Result<Vec<(ObjectId, u128, u128)>> {
        index::ids_range_exact(&self.t, self.txn, space, first, last)
    }

    /// Objects whose range contains `[first, last]`, including exact.
    pub fn range_less_specific(
        &self,
        space: Space,
        first: u128,
        last: u128,
    ) -> Result<Vec<(ObjectId, u128, u128)>> {
        index::ids_range_less_specific(&self.t, self.txn, space, first, last)
    }

    /// Objects whose range lies within `[first, last]`, excluding exact.
    pub fn range_more_specific(
        &self,
        space: Space,
        first: u128,
        last: u128,
    ) -> Result<Vec<(ObjectId, u128, u128)>> {
        index::ids_range_more_specific(&self.t, self.txn, space, first, last)
    }

    /// Objects whose range starts at or below `first`, whatever its end.
    pub fn range_first_at_most(
        &self,
        space: Space,
        first: u128,
    ) -> Result<Vec<(ObjectId, u128, u128)>> {
        index::ids_range_first_at_most(&self.t, self.txn, space, first)
    }

    /// Objects with this `asn_first`.
    pub fn ids_by_asn_first(&self, asn: u32) -> Result<Vec<ObjectId>> {
        index::ids_asn_first(&self.t, self.txn, asn)
    }

    /// route/route6 objects of `source` originated by `asn`.
    pub fn routes_for_origin(
        &self,
        source: &str,
        asn: u32,
        ip_version: Option<u8>,
    ) -> Result<Vec<OriginRoute>> {
        index::routes_for_origin(&self.t, self.txn, source, asn, ip_version)
    }

    // ---- journal ----

    /// One journal entry.
    pub fn journal_entry(
        &self,
        source: &str,
        serial_nrtm: i64,
    ) -> Result<Option<JournalEntryRef<'a>>> {
        query::journal_entry(&self.t, self.txn, source, serial_nrtm)
    }

    /// Journal entries of a source with `start <= serial_nrtm <= end`, in
    /// serial order; all sources (source, serial order) when `source` is
    /// `None`.
    pub fn journal(
        &self,
        source: Option<&str>,
        start: Option<i64>,
        end: Option<i64>,
    ) -> Result<impl Iterator<Item = Result<JournalEntryRef<'a>>> + 'a> {
        let mut p = Vec::new();
        if let Some(s) = source {
            push_str(&mut p, s.as_bytes());
        }
        use std::ops::Bound;
        let lo: Bound<Vec<u8>> = match (source, start) {
            (Some(_), Some(s)) => {
                let mut k = p.clone();
                k.extend_from_slice(&serial_bytes(s));
                Bound::Included(k)
            }
            (Some(_), None) => Bound::Included(p.clone()),
            (None, _) => Bound::Unbounded,
        };
        let hi: Bound<Vec<u8>> = match (source, end) {
            (Some(_), Some(e)) => {
                let mut k = p.clone();
                k.extend_from_slice(&serial_bytes(e));
                Bound::Included(k)
            }
            (Some(_), None) => {
                let mut k = p.clone();
                k.extend_from_slice(&[0xFF; 9]);
                Bound::Included(k)
            }
            (None, _) => Bound::Unbounded,
        };
        let txn = self.txn;
        let iter = self.t.journal.range(
            txn,
            &(
                lo.as_ref().map(|v| v.as_slice()),
                hi.as_ref().map(|v| v.as_slice()),
            ),
        )?;
        Ok(iter.map(|item| {
            let (_, v) = item?;
            Ok(decode::<JournalEntryRef<'a>>(v)?)
        }))
    }

    /// Journal entries with `serial_global >= start`, in `serial_global`
    /// order.
    pub fn journal_by_serial_global(
        &self,
        start: i64,
    ) -> Result<impl Iterator<Item = Result<JournalEntryRef<'a>>> + 'a> {
        let lo = serial_bytes(start).to_vec();
        let t = self.t;
        let txn = self.txn;
        let iter = t.journal_global.range(
            txn,
            &(
                std::ops::Bound::Included(lo.as_slice()),
                std::ops::Bound::Unbounded,
            ),
        )?;
        Ok(iter.map(move |item| {
            let (_, key) = item?;
            let v = t
                .journal
                .get(txn, key)?
                .ok_or(StoreError::Corrupt("journal_global"))?;
            Ok(decode::<JournalEntryRef<'a>>(v)?)
        }))
    }

    /// `MAX(serial_global)` over the whole journal
    /// (`RPSLDatabaseJournalStatisticsQuery`), `None` when it is empty.
    pub fn max_serial_global(&self) -> Result<Option<i64>> {
        match self.t.journal_global.last(self.txn)? {
            Some((k, _)) => Ok(Some(
                crate::keys::serial_from(k).ok_or(StoreError::Corrupt("journal_global"))?,
            )),
            None => Ok(None),
        }
    }

    /// `MAX(timestamp)` over the whole journal
    /// (`RPSLDatabaseJournalStatisticsQuery`), `None` when it is empty.
    pub fn max_journal_timestamp(&self) -> Result<Option<crate::model::Timestamp>> {
        let mut max: Option<crate::model::Timestamp> = None;
        for item in self.t.journal.iter(self.txn)? {
            let (_, v) = item?;
            let e: JournalEntryRef<'_> = decode(v)?;
            if max.is_none_or(|m| e.timestamp > m) {
                max = Some(e.timestamp);
            }
        }
        Ok(max)
    }

    /// The last value handed out by the `serial_global` sequence.
    pub fn serial_global_last_value(&self) -> Result<i64> {
        query::serial_global_last(&self.t, self.txn)
    }

    // ---- database_status ----

    /// The status row of a source.
    pub fn database_status(&self, source: &str) -> Result<Option<DatabaseStatus>> {
        query::status(&self.t, self.txn, source)
    }

    /// Every status row, by source.
    pub fn database_statuses(&self) -> Result<Vec<DatabaseStatus>> {
        let mut out = Vec::new();
        for item in self.t.status.iter(self.txn)? {
            let (_, v) = item?;
            out.push(decode(v)?);
        }
        Ok(out)
    }

    // ---- roa_object ----

    /// Every ROA, in (ip_version, prefix, asn, max_length, trust_anchor) order.
    pub fn roas(&self) -> Result<Vec<RoaRow>> {
        let mut out = Vec::new();
        for item in self.t.roa.iter(self.txn)? {
            let (k, v) = item?;
            out.push(roa_from_kv(k, v)?);
        }
        Ok(out)
    }

    /// ROAs whose prefix equals or contains `prefix` (`prefix >>= ...`).
    pub fn roas_covering(&self, prefix: &IpPrefix) -> Result<Vec<RoaRow>> {
        let ver = prefix.version();
        let (bits, width) = if ver == 4 { (32, 4) } else { (128, 16) };
        let mut out = Vec::new();
        for len in 0..=prefix.len {
            let mut p = vec![ver];
            crate::keys::push_uint(&mut p, crate::keys::mask(prefix.first(), len, bits), width);
            p.push(len);
            for item in self.t.roa.prefix_iter(self.txn, &p)? {
                let (k, v) = item?;
                out.push(roa_from_kv(k, v)?);
            }
        }
        Ok(out)
    }

    // ---- small tables ----

    /// Every suspended object, by row UUID.
    pub fn suspended_objects(&self) -> Result<Vec<SuspendedObjectRow>> {
        self.all(self.t.suspended)
    }

    /// Suspended objects listing `mntner` in `mntners`.
    pub fn suspended_by_mntner(&self, mntner: &str) -> Result<Vec<SuspendedObjectRow>> {
        let mut p = Vec::new();
        push_str(&mut p, mntner.as_bytes());
        let mut out = Vec::new();
        for item in self.t.suspended_mntner.prefix_iter(self.txn, &p)? {
            let (k, _) = item?;
            if let Some(b) = self.t.suspended.get(self.txn, &k[p.len()..])? {
                out.push(decode(b)?);
            }
        }
        Ok(out)
    }

    /// Every protected name, by row UUID.
    pub fn protected_names(&self) -> Result<Vec<ProtectedNameRow>> {
        self.all(self.t.protected_name)
    }

    /// Protected names with this source and name.
    pub fn protected_name(&self, source: &str, name: &str) -> Result<Vec<ProtectedNameRow>> {
        let mut p = Vec::new();
        push_str(&mut p, source.as_bytes());
        push_str(&mut p, name.as_bytes());
        let mut out = Vec::new();
        for item in self.t.protected_name_idx.prefix_iter(self.txn, &p)? {
            let (k, _) = item?;
            if let Some(b) = self.t.protected_name.get(self.txn, &k[p.len()..])? {
                out.push(decode(b)?);
            }
        }
        Ok(out)
    }

    /// Every `setting` row, by name.
    pub fn settings(&self) -> Result<Vec<SettingRow>> {
        self.all(self.t.setting)
    }

    /// Every `auth_user` row.
    pub fn auth_users(&self) -> Result<Vec<AuthUserRow>> {
        self.all(self.t.auth_user)
    }

    /// Every `auth_permission` row.
    pub fn auth_permissions(&self) -> Result<Vec<AuthPermissionRow>> {
        self.all(self.t.auth_permission)
    }

    /// Every `auth_mntner` row.
    pub fn auth_mntners(&self) -> Result<Vec<AuthMntnerRow>> {
        self.all(self.t.auth_mntner)
    }

    /// Every `auth_api_token` row.
    pub fn auth_api_tokens(&self) -> Result<Vec<AuthApiTokenRow>> {
        self.all(self.t.auth_api_token)
    }

    /// The API token with this `token` value.
    pub fn auth_api_token_by_token(&self, token: &Uuid) -> Result<Option<AuthApiTokenRow>> {
        let Some(pk) = self.t.api_token_idx.get(self.txn, token.as_bytes())? else {
            return Ok(None);
        };
        match self.t.auth_api_token.get(self.txn, pk)? {
            Some(b) => Ok(Some(decode(b)?)),
            None => Ok(None),
        }
    }

    /// Every `auth_webauthn` row.
    pub fn auth_webauthns(&self) -> Result<Vec<AuthWebAuthnRow>> {
        self.all(self.t.auth_webauthn)
    }

    /// Every `change_log` row.
    pub fn change_logs(&self) -> Result<Vec<ChangeLogRow>> {
        self.all(self.t.change_log)
    }

    /// Every PGP keyring entry, as `(fingerprint, encoded key)`, in
    /// fingerprint order. The encoding belongs to the `rpsl` crate's
    /// keyring.
    pub fn pgp_keyring(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let mut out = Vec::new();
        for item in self.t.pgp_keyring.iter(self.txn)? {
            let (k, v) = item?;
            out.push((String::from_utf8_lossy(k).into_owned(), v.to_vec()));
        }
        Ok(out)
    }

    fn all<T: serde::de::DeserializeOwned>(&self, table: crate::env::Table) -> Result<Vec<T>> {
        let mut out = Vec::new();
        for item in table.iter(self.txn)? {
            let (_, v) = item?;
            out.push(decode(v)?);
        }
        Ok(out)
    }
}

fn roa_from_kv(k: &[u8], v: &[u8]) -> Result<RoaRow> {
    let bad = || StoreError::Corrupt("roa key");
    let ver = *k.first().ok_or_else(bad)?;
    let width = if ver == 4 { 4 } else { 16 };
    let addr = crate::keys::read_uint(&k[1..], width).ok_or_else(bad)?;
    let mut i = 1 + width;
    let len = *k.get(i).ok_or_else(bad)?;
    i += 1;
    let asn = crate::keys::serial_from(&k[i..]).ok_or_else(bad)?;
    i += 8;
    let max_length = crate::keys::serial_from(&k[i..]).ok_or_else(bad)?;
    i += 8;
    let trust_anchor = match k.get(i) {
        Some(0) => None,
        Some(1) => Some(crate::keys::take_string(&k[i + 1..]).ok_or_else(bad)?.0),
        _ => return Err(bad()),
    };
    let ip = if ver == 4 {
        std::net::IpAddr::V4(std::net::Ipv4Addr::from(addr as u32))
    } else {
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr))
    };
    let val: RoaValue = decode(v)?;
    Ok(RoaRow {
        pk: val.pk,
        prefix: IpPrefix::new(ip, len).ok_or_else(bad)?,
        asn,
        max_length,
        trust_anchor,
        ip_version: ver,
        created: val.created,
    })
}
