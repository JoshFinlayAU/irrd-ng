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
//! table's key, so re-running an import over the same store changes nothing
//! and duplicates nothing.

use std::net::IpAddr;

use store::{
    AuthApiTokenRow, AuthMntnerRow, AuthPermissionRow, AuthUserRow, AuthWebAuthnRow, ChangeLogRow,
    IpPrefix, Json, ProtectedNameRow, RoaRow, RpslObjectRow, SettingRow, Store, SuspendedObjectRow,
    WriteTx,
};

use crate::rows::{self, Batch};
use crate::types::{self, Inet};
use crate::{Sink, messages};

/// Rows per store write transaction.
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
    fn put(&self, tx: &mut WriteTx<'_, '_>) -> store::Result<()> {
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
}

impl<'s> StoreSink<'s> {
    pub fn new(store: &'s Store) -> Self {
        StoreSink {
            store,
            pending: Vec::with_capacity(WRITE_BATCH_ROWS),
            written: 0,
        }
    }

    /// Rows written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    fn flush(&mut self) -> Result<(), StoreSinkError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let rows = std::mem::take(&mut self.pending);
        let n = rows.len() as u64;
        // The closure can be re-run after a map resize, so it only reads
        // `rows`.
        self.store.write(move |tx| {
            for r in &rows {
                r.put(tx)?;
            }
            Ok(())
        })?;
        self.written += n;
        self.pending = Vec::with_capacity(WRITE_BATCH_ROWS);
        Ok(())
    }

    fn push(&mut self, row: Row) -> Result<(), StoreSinkError> {
        self.pending.push(row);
        if self.pending.len() >= WRITE_BATCH_ROWS {
            self.flush()?;
        }
        Ok(())
    }
}

impl Sink for StoreSink<'_> {
    type Error = StoreSinkError;

    fn write(&mut self, batch: Batch) -> Result<(), StoreSinkError> {
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
        self.flush()
    }
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
