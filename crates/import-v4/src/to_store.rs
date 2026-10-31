//! The store as an import [`Sink`]: v4 rows mapped onto `store`'s row types.
//!
//! Every column is carried. Where the store's type is narrower than v4's
//! column, the value is checked, never coerced: a value that does not fit
//! fails the import with the row named, so nothing is lost silently.
//! `ip_size` is not stored (the store derives it from `ip_first`/`ip_last`),
//! so the derivation is checked against v4's value for every row instead.
//!
//! Rows are buffered and written in transactions of about
//! [`WRITE_BATCH_ROWS`] rows. Every put is an idempotent upsert on the
//! table's key, and rows the store holds but the source no longer has are
//! deleted (unjournaled): the big tables by a merge-join against the
//! source's key-ordered stream, the small ones by a set difference at the
//! end. So a re-import leaves the store equal to the source, and re-running
//! over an unchanged source changes nothing.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

use store::{
    AuthApiTokenRow, AuthMntnerRow, AuthPermissionRow, AuthTable, AuthUserRow, AuthWebAuthnRow,
    ChangeLogRow, IpPrefix, Json, ProtectedNameRow, RoaRow, RpslObjectRow, SettingRow, Store,
    SuspendedObjectRow, Uuid, WriteTx,
};

use crate::rows::{self, Batch};
use crate::types::{self, Inet};
use crate::{Sink, messages};

/// Rows per store write transaction, by default.
pub const WRITE_BATCH_ROWS: usize = 50_000;

#[derive(Debug, thiserror::Error)]
pub enum StoreSinkError {
    #[error(transparent)]
    Store(#[from] store::StoreError),
    #[error("{0}")]
    Convert(String),
}

/// One converted row, ready to put.
#[derive(Debug, Clone)]
enum Row {
    Object(Box<RpslObjectRow>),
    Journal(Box<store::JournalEntry>),
    Status(Box<store::DatabaseStatus>),
    Roa(RoaRow),
    Suspended(Box<SuspendedObjectRow>),
    Protected(ProtectedNameRow),
    Setting(SettingRow),
    User(AuthUserRow),
    Permission(AuthPermissionRow),
    Mntner(AuthMntnerRow),
    Token(AuthApiTokenRow),
    Webauthn(AuthWebAuthnRow),
    ChangeLog(Box<ChangeLogRow>),
    SerialGlobal(i64),
}

impl Row {
    /// Whether the store already holds exactly this row. A re-run then
    /// writes nothing for it: with LMDB's copy-on-write even an identical
    /// upsert rewrites every page on its path, which on a store that does
    /// not fit in memory makes a re-import far slower than the first run.
    /// Checked for objects and the journal, the tables that grow to millions
    /// of rows with large pages; ROAs are small and have no point lookup.
    fn unchanged(&self, tx: &WriteTx<'_, '_>) -> store::Result<bool> {
        let view = tx.read_unflushed();
        Ok(match self {
            Row::Object(r) => view
                .object(&r.source, &r.object_class, &r.rpsl_pk)?
                .is_some_and(|old| old.to_row() == **r),
            Row::Journal(e) => view
                .journal_entry(&e.source, e.serial_nrtm)?
                .is_some_and(|old| old.to_entry() == **e),
            _ => false,
        })
    }

    fn put(&self, tx: &mut WriteTx<'_, '_>) -> store::Result<()> {
        if self.unchanged(tx)? {
            return Ok(());
        }
        match self {
            Row::Object(r) => tx.put_rpsl_object(r),
            Row::Journal(r) => tx.put_journal_entry(r),
            Row::Status(r) => tx.put_database_status(r),
            Row::Roa(r) => tx.put_roa(r),
            Row::Suspended(r) => tx.put_suspended_object(r),
            Row::Protected(r) => tx.put_protected_name(r),
            Row::Setting(r) => tx.put_setting(r),
            Row::User(r) => tx.put_auth_user(r),
            Row::Permission(r) => tx.put_auth_permission(r),
            Row::Mntner(r) => tx.put_auth_mntner(r),
            Row::Token(r) => tx.put_auth_api_token(r),
            Row::Webauthn(r) => tx.put_auth_webauthn(r),
            Row::ChangeLog(r) => tx.put_change_log(r),
            Row::SerialGlobal(v) => tx.set_serial_global_last_value(*v),
        }
    }
}

/// Writes imported rows into a [`Store`].
#[derive(Debug)]
pub struct StoreSink<'s> {
    store: &'s Store,
    pending: Vec<Row>,
    written: u64,
    batch_rows: usize,
    /// How far the merge-join prune of each big table has got.
    pruned: Prune,
    /// Keys the source holds in the small tables, for the set difference.
    seen: Seen,
    deleted: Deleted,
}

/// The store keys each big table's prune has covered (opaque, from
/// `store::Pruned::through`).
#[derive(Debug, Default)]
struct Prune {
    objects: Option<Vec<u8>>,
    journal: Option<Vec<u8>>,
    roas: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct Seen {
    status: HashSet<String>,
    suspended: HashSet<Uuid>,
    protected: HashSet<Uuid>,
    settings: HashSet<String>,
    users: HashSet<Uuid>,
    permissions: HashSet<Uuid>,
    mntners: HashSet<Uuid>,
    tokens: HashSet<Uuid>,
    webauthn: HashSet<Uuid>,
    change_log: HashSet<Uuid>,
}

/// Rows deleted per table because the source no longer has them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Deleted(pub BTreeMap<&'static str, u64>);

impl Deleted {
    pub fn get(&self, table: &str) -> u64 {
        self.0.get(table).copied().unwrap_or(0)
    }

    fn add(&mut self, table: &'static str, n: u64) {
        *self.0.entry(table).or_default() += n;
    }
}

impl<'s> StoreSink<'s> {
    pub fn new(store: &'s Store) -> Self {
        Self::with_batch_rows(store, WRITE_BATCH_ROWS)
    }

    /// Commit every `batch_rows` rows. Larger batches mean fewer commits,
    /// and with LMDB's copy-on-write each commit rewrites every page it
    /// touched, so on disk this trades memory for import time.
    pub fn with_batch_rows(store: &'s Store, batch_rows: usize) -> Self {
        let batch_rows = batch_rows.max(1);
        StoreSink {
            store,
            pending: Vec::with_capacity(batch_rows.min(WRITE_BATCH_ROWS)),
            written: 0,
            batch_rows,
            pruned: Prune::default(),
            seen: Seen::default(),
            deleted: Deleted::default(),
        }
    }

    /// Rows deleted per table, complete once the import has finished.
    pub fn deleted(&self) -> &Deleted {
        &self.deleted
    }

    /// Rows written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Write the pending rows in one transaction. A re-import must leave
    /// the store equal to the source, so first each big table is pruned as
    /// a merge-join: the source streams it in the store's key order, so the
    /// store keys between the previous batch's highest key and this batch's
    /// that the batch does not hold are gone from the source. With
    /// `to_end`, the rest of each big table goes too (the stream is over).
    fn flush_with(&mut self, to_end: bool) -> Result<(), StoreSinkError> {
        if self.pending.is_empty() && !to_end {
            return Ok(());
        }
        let rows = std::mem::take(&mut self.pending);
        let n = rows.len() as u64;
        let after = (
            self.pruned.objects.clone(),
            self.pruned.journal.clone(),
            self.pruned.roas.clone(),
        );
        // The closure can be re-run after a map resize, so it only reads
        // `rows` and `after`, and hands the new prune positions back.
        let (objects, journal, roas) = self.store.write(move |tx| {
            let mut obj_keys = Vec::new();
            let mut jr_keys = Vec::new();
            let mut roa_keys = Vec::new();
            for r in &rows {
                match r {
                    Row::Object(o) => obj_keys.push((
                        o.source.as_str(),
                        o.object_class.as_str(),
                        o.rpsl_pk.as_str(),
                    )),
                    Row::Journal(e) => jr_keys.push((e.source.as_str(), e.serial_nrtm)),
                    Row::Roa(r) => roa_keys.push(r),
                    _ => {}
                }
            }
            let objects = tx.prune_rpsl_objects(after.0.as_deref(), &obj_keys, to_end)?;
            let journal = tx.prune_journal(after.1.as_deref(), &jr_keys, to_end)?;
            let roas = tx.prune_roas(after.2.as_deref(), &roa_keys, to_end)?;
            for r in &rows {
                r.put(tx)?;
            }
            Ok((objects, journal, roas))
        })?;
        self.deleted.add("rpsl_objects", objects.deleted);
        self.deleted.add("rpsl_database_journal", journal.deleted);
        self.deleted.add("roa_object", roas.deleted);
        self.pruned = Prune {
            objects: objects.through,
            journal: journal.through,
            roas: roas.through,
        };
        self.written += n;
        self.pending = Vec::with_capacity(self.batch_rows.min(WRITE_BATCH_ROWS));
        Ok(())
    }

    fn flush(&mut self) -> Result<(), StoreSinkError> {
        self.flush_with(false)
    }

    /// The small tables: delete what the store holds and the source does
    /// not, as a set difference.
    fn prune_small_tables(&mut self) -> Result<(), StoreSinkError> {
        let seen = std::mem::take(&mut self.seen);
        let counts = self.store.write(move |tx| {
            let v = tx.read_unflushed();
            let status: Vec<String> = v
                .database_statuses()?
                .into_iter()
                .map(|r| r.source)
                .filter(|k| !seen.status.contains(k))
                .collect();
            let suspended = gone(
                v.suspended_objects()?.into_iter().map(|r| r.pk),
                &seen.suspended,
            );
            let protected = gone(
                v.protected_names()?.into_iter().map(|r| r.pk),
                &seen.protected,
            );
            let settings: Vec<String> = v
                .settings()?
                .into_iter()
                .map(|r| r.name)
                .filter(|k| !seen.settings.contains(k))
                .collect();
            let users = gone(v.auth_users()?.into_iter().map(|r| r.pk), &seen.users);
            let permissions = gone(
                v.auth_permissions()?.into_iter().map(|r| r.pk),
                &seen.permissions,
            );
            let mntners = gone(v.auth_mntners()?.into_iter().map(|r| r.pk), &seen.mntners);
            let tokens = gone(v.auth_api_tokens()?.into_iter().map(|r| r.pk), &seen.tokens);
            let webauthn = gone(
                v.auth_webauthns()?.into_iter().map(|r| r.pk),
                &seen.webauthn,
            );
            let change_log = gone(v.change_logs()?.into_iter().map(|r| r.pk), &seen.change_log);
            for k in &status {
                tx.delete_database_status(k)?;
            }
            for k in &suspended {
                tx.delete_suspended_object_raw(k)?;
            }
            for k in &protected {
                tx.delete_protected_name_raw(k)?;
            }
            for k in &settings {
                tx.delete_setting_raw(k)?;
            }
            for k in &tokens {
                tx.delete_auth_api_token_raw(k)?;
            }
            for (table, keys) in [
                (AuthTable::User, &users),
                (AuthTable::Permission, &permissions),
                (AuthTable::Mntner, &mntners),
                (AuthTable::Webauthn, &webauthn),
                (AuthTable::ChangeLog, &change_log),
            ] {
                for k in keys {
                    tx.delete_auth_row_raw(table, k)?;
                }
            }
            let n = |v: usize| v as u64;
            Ok([
                ("database_status", n(status.len())),
                ("rpsl_objects_suspended", n(suspended.len())),
                ("protected_rpsl_name", n(protected.len())),
                ("setting", n(settings.len())),
                ("auth_user", n(users.len())),
                ("auth_permission", n(permissions.len())),
                ("auth_mntner", n(mntners.len())),
                ("auth_api_token", n(tokens.len())),
                ("auth_webauthn", n(webauthn.len())),
                ("change_log", n(change_log.len())),
            ])
        })?;
        for (table, n) in counts {
            self.deleted.add(table, n);
        }
        Ok(())
    }

    fn push(&mut self, row: Row) -> Result<(), StoreSinkError> {
        self.pending.push(row);
        if self.pending.len() >= self.batch_rows {
            self.flush()?;
        }
        Ok(())
    }
}

impl Sink for StoreSink<'_> {
    type Error = StoreSinkError;

    fn write(&mut self, batch: Batch) -> Result<(), StoreSinkError> {
        self.note_keys(&batch);
        match batch {
            Batch::RpslObjects(v) => each(self, v, |r| Ok(Row::Object(Box::new(object(r)?)))),
            Batch::Journal(v) => each(self, v, |r| Ok(Row::Journal(Box::new(journal(r)?)))),
            Batch::DatabaseStatus(v) => each(self, v, |r| Ok(Row::Status(Box::new(status(r)?)))),
            Batch::Roas(v) => each(self, v, |r| Ok(Row::Roa(roa(r)?))),
            Batch::Suspended(v) => each(self, v, |r| {
                Ok(Row::Suspended(Box::new(SuspendedObjectRow {
                    pk: r.pk,
                    rpsl_pk: r.rpsl_pk,
                    source: r.source,
                    object_class: r.object_class,
                    object_text: r.object_text,
                    mntners: r.mntners,
                    timestamp: ts(r.timestamp),
                    original_created: ts(r.original_created),
                    original_updated: ts(r.original_updated),
                })))
            }),
            Batch::ProtectedNames(v) => each(self, v, |r| {
                Ok(Row::Protected(ProtectedNameRow {
                    pk: r.pk,
                    rpsl_pk: r.rpsl_pk,
                    source: r.source,
                    object_class: r.object_class,
                    protected_name: r.protected_name,
                    created: ts(r.created),
                }))
            }),
            Batch::Settings(v) => each(self, v, |r| {
                Ok(Row::Setting(SettingRow {
                    name: r.name,
                    value: r.value,
                    created: ts(r.created),
                }))
            }),
            Batch::AuthUsers(v) => each(self, v, |r| {
                Ok(Row::User(AuthUserRow {
                    pk: r.pk,
                    email: r.email,
                    name: r.name,
                    password: r.password,
                    totp_secret: r.totp_secret,
                    totp_last_used: r.totp_last_used,
                    active: r.active,
                    override_: r.override_,
                    created: ts(r.created),
                    updated: ts(r.updated),
                }))
            }),
            Batch::AuthMntners(v) => each(self, v, |r| {
                Ok(Row::Mntner(AuthMntnerRow {
                    pk: r.pk,
                    rpsl_mntner_pk: r.rpsl_mntner_pk,
                    rpsl_mntner_obj_id: r.rpsl_mntner_obj_id,
                    rpsl_mntner_source: r.rpsl_mntner_source,
                    migration_token: r.migration_token,
                    created: ts(r.created),
                    updated: ts(r.updated),
                }))
            }),
            Batch::AuthPermissions(v) => each(self, v, |r| {
                Ok(Row::Permission(AuthPermissionRow {
                    pk: r.pk,
                    user_id: r.user_id,
                    mntner_id: r.mntner_id,
                    user_management: r.user_management,
                    created: ts(r.created),
                    updated: ts(r.updated),
                }))
            }),
            Batch::AuthApiTokens(v) => each(self, v, |r| {
                Ok(Row::Token(AuthApiTokenRow {
                    pk: r.pk,
                    token: r.token,
                    name: r.name,
                    creator_id: r.creator_id,
                    mntner_id: r.mntner_id,
                    ip_restriction: r.ip_restriction,
                    enabled_webapi: r.enabled_webapi,
                    enabled_email: r.enabled_email,
                    created: ts(r.created),
                    updated: ts(r.updated),
                }))
            }),
            Batch::AuthWebauthn(v) => each(self, v, |r| {
                Ok(Row::Webauthn(AuthWebAuthnRow {
                    pk: r.pk,
                    user_id: r.user_id,
                    name: r.name,
                    credential_id: r.credential_id,
                    credential_public_key: r.credential_public_key,
                    credential_sign_count: i64::from(r.credential_sign_count),
                    created: ts(r.created),
                    last_used: ts(r.last_used),
                }))
            }),
            Batch::ChangeLog(v) => each(self, v, |r| Ok(Row::ChangeLog(Box::new(change_log(r)?)))),
            Batch::SerialGlobalLastValue(last) => self.push(Row::SerialGlobal(last)),
        }
    }

    fn finish(&mut self) -> Result<(), StoreSinkError> {
        // The last batch, then everything the big tables hold beyond it.
        self.flush_with(true)?;
        self.prune_small_tables()
    }
}

impl StoreSink<'_> {
    /// Remember the small tables' keys for the set difference at the end.
    fn note_keys(&mut self, batch: &Batch) {
        let s = &mut self.seen;
        match batch {
            Batch::DatabaseStatus(v) => s.status.extend(v.iter().map(|r| r.source.clone())),
            Batch::Suspended(v) => s.suspended.extend(v.iter().map(|r| r.pk)),
            Batch::ProtectedNames(v) => s.protected.extend(v.iter().map(|r| r.pk)),
            Batch::Settings(v) => s.settings.extend(v.iter().map(|r| r.name.clone())),
            Batch::AuthUsers(v) => s.users.extend(v.iter().map(|r| r.pk)),
            Batch::AuthPermissions(v) => s.permissions.extend(v.iter().map(|r| r.pk)),
            Batch::AuthMntners(v) => s.mntners.extend(v.iter().map(|r| r.pk)),
            Batch::AuthApiTokens(v) => s.tokens.extend(v.iter().map(|r| r.pk)),
            Batch::AuthWebauthn(v) => s.webauthn.extend(v.iter().map(|r| r.pk)),
            Batch::ChangeLog(v) => s.change_log.extend(v.iter().map(|r| r.pk)),
            Batch::RpslObjects(_)
            | Batch::Journal(_)
            | Batch::Roas(_)
            | Batch::SerialGlobalLastValue(_) => {}
        }
    }
}

/// The keys the store holds that the source does not.
fn gone(store_keys: impl Iterator<Item = Uuid>, source: &HashSet<Uuid>) -> Vec<Uuid> {
    store_keys.filter(|k| !source.contains(k)).collect()
}

fn each<T>(
    sink: &mut StoreSink<'_>,
    rows: Vec<T>,
    convert: impl Fn(T) -> Result<Row, StoreSinkError>,
) -> Result<(), StoreSinkError> {
    for r in rows {
        sink.push(convert(r)?)?;
    }
    Ok(())
}

fn ts(t: types::Timestamp) -> store::Timestamp {
    store::Timestamp(t.unix_micros())
}

fn json(j: &types::JsonText, what: &str) -> Result<Json, StoreSinkError> {
    Json::canonical(&j.0)
        .map_err(|e| StoreSinkError::Convert(messages::bad_value(what, &e.to_string())))
}

/// An `inet` column the store keeps as a bare address: the mask must cover
/// the whole address, as v4 always writes it.
fn host(i: Inet, what: &str) -> Result<IpAddr, StoreSinkError> {
    let full = if i.addr.is_ipv4() { 32 } else { 128 };
    if i.prefix_len != full {
        return Err(StoreSinkError::Convert(messages::bad_value(
            what,
            &i.to_string(),
        )));
    }
    Ok(i.addr)
}

/// A `cidr` column. PostgreSQL guarantees zero host bits; checked anyway,
/// since `IpPrefix::new` would clear them silently.
fn cidr(i: Inet, what: &str) -> Result<IpPrefix, StoreSinkError> {
    IpPrefix::new(i.addr, i.prefix_len)
        .filter(|p| p.addr == i.addr)
        .ok_or_else(|| StoreSinkError::Convert(messages::bad_value(what, &i.to_string())))
}

fn narrow<T: TryFrom<i64>>(v: Option<i64>, what: &str) -> Result<Option<T>, StoreSinkError> {
    v.map(|n| {
        T::try_from(n)
            .map_err(|_| StoreSinkError::Convert(messages::bad_value(what, &n.to_string())))
    })
    .transpose()
}

fn object(r: rows::RpslObject) -> Result<RpslObjectRow, StoreSinkError> {
    let what = |col: &str| {
        format!(
            "rpsl_objects.{col} of {}/{}/{}",
            r.source, r.object_class, r.rpsl_pk
        )
    };
    let ip_first = r.ip_first.map(|i| host(i, &what("ip_first"))).transpose()?;
    let ip_last = r.ip_last.map(|i| host(i, &what("ip_last"))).transpose()?;
    // ip_size is derived by the store; it must come out as v4 stored it.
    let derived = store::ip_size(ip_first.as_ref(), ip_last.as_ref());
    if derived.as_deref() != r.ip_size.as_ref().map(|n| n.0.as_str()) {
        return Err(StoreSinkError::Convert(messages::ip_size_mismatch(
            &what("ip_size"),
            r.ip_size.as_ref().map_or("NULL", |n| n.0.as_str()),
            derived.as_deref().unwrap_or("NULL"),
        )));
    }
    Ok(RpslObjectRow {
        pk: r.pk,
        parsed_data: json(&r.parsed_data, &what("parsed_data"))?,
        ip_version: narrow(r.ip_version.map(i64::from), &what("ip_version"))?,
        ip_first,
        ip_last,
        prefix_length: narrow(r.prefix_length.map(i64::from), &what("prefix_length"))?,
        prefix: r.prefix.map(|i| cidr(i, &what("prefix"))).transpose()?,
        asn_first: narrow(r.asn_first, &what("asn_first"))?,
        asn_last: narrow(r.asn_last, &what("asn_last"))?,
        rpki_status: enum_map(r.rpki_status.label(), store::RpkiStatus::from_pg_label)?,
        scopefilter_status: enum_map(
            r.scopefilter_status.label(),
            store::ScopeFilterStatus::from_pg_label,
        )?,
        route_preference_status: enum_map(
            r.route_preference_status.label(),
            store::RoutePreferenceStatus::from_pg_label,
        )?,
        created: ts(r.created),
        updated: ts(r.updated),
        object_text: r.object_text,
        object_class: r.object_class,
        source: r.source,
        rpsl_pk: r.rpsl_pk,
    })
}

fn enum_map<T>(label: &str, f: fn(&str) -> Option<T>) -> Result<T, StoreSinkError> {
    f(label).ok_or_else(|| StoreSinkError::Convert(messages::bad_value("enum label", label)))
}

fn journal(r: rows::JournalEntry) -> Result<store::JournalEntry, StoreSinkError> {
    let what = |col: &str| {
        format!(
            "rpsl_database_journal.{col} of {} serial {}",
            r.source, r.serial_nrtm
        )
    };
    let serial_global = r.serial_global.ok_or_else(|| {
        StoreSinkError::Convert(messages::bad_value(&what("serial_global"), "NULL"))
    })?;
    Ok(store::JournalEntry {
        pk: r.pk,
        serial_global,
        origin: enum_map(r.origin.label(), store::JournalEntryOrigin::from_pg_label)?,
        serial_nrtm: i64::from(r.serial_nrtm),
        operation: enum_map(r.operation.label(), store::DatabaseOperation::from_pg_label)?,
        timestamp: ts(r.timestamp),
        rpsl_pk: r.rpsl_pk,
        source: r.source,
        object_class: r.object_class,
        object_text: r.object_text,
    })
}

fn status(r: rows::DatabaseStatus) -> Result<store::DatabaseStatus, StoreSinkError> {
    let i = |v: Option<i32>| v.map(i64::from);
    let hashes = r
        .nrtm4_client_previous_file_hashes
        .as_ref()
        .map(|j| json(j, "database_status.nrtm4_client_previous_file_hashes"))
        .transpose()?;
    let deltas = r
        .nrtm4_server_previous_deltas
        .as_ref()
        .map(|j| json(j, "database_status.nrtm4_server_previous_deltas"))
        .transpose()?;
    Ok(store::DatabaseStatus {
        pk: r.pk,
        source: r.source,
        serial_oldest_seen: i(r.serial_oldest_seen),
        serial_newest_seen: i(r.serial_newest_seen),
        serial_oldest_journal: i(r.serial_oldest_journal),
        serial_newest_journal: i(r.serial_newest_journal),
        serial_last_export: i(r.serial_last_export),
        serial_newest_mirror: i(r.serial_newest_mirror),
        nrtm4_client_session_id: r.nrtm4_client_session_id,
        nrtm4_client_version: i(r.nrtm4_client_version),
        nrtm4_client_current_key: r.nrtm4_client_current_key,
        nrtm4_client_next_key: r.nrtm4_client_next_key,
        nrtm4_client_previous_file_hashes: hashes,
        nrtm4_server_session_id: r.nrtm4_server_session_id,
        nrtm4_server_version: i(r.nrtm4_server_version),
        nrtm4_server_last_update_notification_file_update: r
            .nrtm4_server_last_update_notification_file_update
            .map(ts),
        nrtm4_server_last_snapshot_version: i(r.nrtm4_server_last_snapshot_version),
        nrtm4_server_last_snapshot_global_serial: i(r.nrtm4_server_last_snapshot_global_serial),
        nrtm4_server_last_snapshot_timestamp: r.nrtm4_server_last_snapshot_timestamp.map(ts),
        nrtm4_server_last_snapshot_filename: r.nrtm4_server_last_snapshot_filename,
        nrtm4_server_last_snapshot_hash: r.nrtm4_server_last_snapshot_hash,
        nrtm4_server_previous_deltas: deltas,
        force_reload: r.force_reload,
        synchronised_serials: r.synchronised_serials,
        last_error: r.last_error,
        last_error_timestamp: r.last_error_timestamp.map(ts),
        rpsl_data_updated: ts(r.rpsl_data_updated),
        created: ts(r.created),
        updated: ts(r.updated),
    })
}

fn roa(r: rows::Roa) -> Result<RoaRow, StoreSinkError> {
    let what = format!("roa_object.prefix of {}", r.pk);
    Ok(RoaRow {
        pk: r.pk,
        prefix: cidr(r.prefix, &what)?,
        asn: r.asn,
        max_length: i64::from(r.max_length),
        trust_anchor: r.trust_anchor,
        ip_version: narrow(Some(i64::from(r.ip_version)), "roa_object.ip_version")?.unwrap_or(0),
        created: ts(r.created),
    })
}

fn change_log(r: rows::ChangeLog) -> Result<ChangeLogRow, StoreSinkError> {
    let request_type = r
        .rpsl_target_request_type
        .map(|t| enum_map(t.label(), store::UpdateRequestType::from_pg_label))
        .transpose()?;
    Ok(ChangeLogRow {
        pk: r.pk,
        auth_by_user_id: r.auth_by_user_id,
        auth_by_user_email: r.auth_by_user_email,
        auth_by_api_key_id: r.auth_by_api_key_id,
        auth_by_api_key_id_fixed: r.auth_by_api_key_id_fixed,
        auth_through_mntner_id: r.auth_through_mntner_id,
        auth_through_rpsl_mntner_pk: r.auth_through_rpsl_mntner_pk,
        auth_by_rpsl_mntner_password: r.auth_by_rpsl_mntner_password,
        auth_by_rpsl_mntner_pgp_key: r.auth_by_rpsl_mntner_pgp_key,
        auth_by_override: r.auth_by_override,
        from_email: r.from_email,
        // The store keeps inet as PostgreSQL's text output.
        from_ip: r.from_ip.map(|i| i.to_string()),
        auth_change_descr: r.auth_change_descr,
        auth_affected_user_id: r.auth_affected_user_id,
        auth_affected_mntner_id: r.auth_affected_mntner_id,
        rpsl_target_request_type: request_type,
        rpsl_target_pk: r.rpsl_target_pk,
        rpsl_target_source: r.rpsl_target_source,
        rpsl_target_object_class: r.rpsl_target_object_class,
        rpsl_target_object_text_old: r.rpsl_target_object_text_old,
        rpsl_target_object_text_new: r.rpsl_target_object_text_new,
        timestamp: ts(r.timestamp),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn inet(s: &str) -> Inet {
        let (a, l) = s.split_once('/').unwrap();
        Inet {
            addr: a.parse().unwrap(),
            prefix_len: l.parse().unwrap(),
            is_cidr: true,
        }
    }

    #[test]
    fn cidr_keeps_every_length() {
        for s in [
            "0.0.0.0/0",
            "192.0.2.0/24",
            "192.0.2.1/32",
            "::/0",
            "2a0c:9c80::/128",
            "2001:db8::/32",
        ] {
            let p = cidr(inet(s), "t").unwrap();
            assert_eq!(format!("{}/{}", p.addr, p.len), s);
        }
        assert!(cidr(inet("192.0.2.1/24"), "t").is_err());
        assert!(cidr(inet("2001:db8::1/64"), "t").is_err());
    }
}
