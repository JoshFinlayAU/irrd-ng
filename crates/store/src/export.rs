//! The canonical JSONL export of the store.
//!
//! One file (or stream) per table, one line per row. The same shape is
//! written from v4's PostgreSQL database by the import tooling, so the
//! three-way load check (v4 loader, irrd-ng loader, irrd-ng import) can
//! diff them line by line.
//!
//! # Format
//!
//! - Each line is a JSON object whose keys are v4's column names. Keys are
//!   sorted bytewise at every level, including inside `parsed_data` and the
//!   other JSON columns. Output is compact (no spaces), with serde_json's
//!   string escaping (`"`, `\\` and control characters escaped, other
//!   characters, non-ASCII included, written as UTF-8).
//! - NULL is `null`. Booleans are `true`/`false`. Integers are JSON numbers,
//!   except `rpsl_objects.ip_size`, which is a decimal string (it reaches
//!   2^128).
//! - UUIDs are lower-case hyphenated strings.
//! - Timestamps are `YYYY-MM-DDTHH:MM:SS.ffffff+00:00`, always UTC and always
//!   six fraction digits.
//! - Enums are the PostgreSQL labels v4 stores, which are the Python member
//!   names: `not_found`, `in_scope`, `visible`, `add_or_update`, `mirror`,
//!   `CREATE`, and so on.
//! - `inet` columns (`ip_first`, `ip_last`) are PostgreSQL's text form of a
//!   host address (no `/32` or `/128`); `cidr` columns (`prefix`) always
//!   carry the length. IPv6 is compressed as PostgreSQL prints it,
//!   including dotted-quad for IPv4-mapped and IPv4-compatible addresses.
//!   `change_log.from_ip` is the stored text.
//! - JSON and JSONB columns (`parsed_data`, `nrtm4_client_previous_file_hashes`,
//!   `nrtm4_server_previous_deltas`) are embedded as JSON values, not
//!   strings.
//! - `bytea` columns (`auth_webauthn.credential_id`,
//!   `credential_public_key`) are PostgreSQL's hex output: `\x` followed by
//!   lower-case hex.
//! - `rpsl_objects_suspended.mntners` is a JSON array of strings.
//!
//! # Row order
//!
//! Strings compare bytewise (UTF-8), numbers numerically, NULL first.
//!
//! | table | order |
//! |---|---|
//! | `rpsl_objects` | source, object_class, rpsl_pk |
//! | `rpsl_database_journal` | source, serial_nrtm |
//! | `database_status` | source |
//! | `roa_object` | ip_version, prefix network address, prefix length, asn, max_length, trust_anchor |
//! | `rpsl_objects_suspended` | source, object_class, rpsl_pk, timestamp, pk |
//! | `protected_rpsl_name` | source, protected_name, object_class, rpsl_pk, created, pk |
//! | `setting` | name |
//! | `auth_user`, `auth_permission`, `auth_mntner`, `auth_api_token`, `auth_webauthn`, `change_log` | pk |
//!
//! Row UUIDs (`pk`) and timestamps differ between independent loads; the
//! comparison masks them where they cannot agree.

use std::io::Write;

use serde_json::{Value, json};

use crate::error::{Result, StoreError};
use crate::model::{InetDisplay, Json, Timestamp, Uuid};
use crate::read::ReadView;

/// Every exportable table, in v4's naming.
pub const EXPORT_TABLES: &[&str] = &[
    "rpsl_objects",
    "rpsl_database_journal",
    "database_status",
    "roa_object",
    "rpsl_objects_suspended",
    "protected_rpsl_name",
    "setting",
    "auth_user",
    "auth_permission",
    "auth_mntner",
    "auth_api_token",
    "auth_webauthn",
    "change_log",
];

fn ts(t: Timestamp) -> Value {
    Value::String(t.to_string())
}

fn ots(t: Option<Timestamp>) -> Value {
    t.map(ts).unwrap_or(Value::Null)
}

fn uuid(u: &Uuid) -> Value {
    Value::String(u.to_string())
}

fn ouuid(u: &Option<Uuid>) -> Value {
    u.as_ref().map(uuid).unwrap_or(Value::Null)
}

fn ojson(j: &Option<Json>) -> Value {
    j.as_ref().map(|j| j.value()).unwrap_or(Value::Null)
}

fn bytea(b: &[u8]) -> Value {
    let mut s = String::with_capacity(2 + b.len() * 2);
    s.push_str("\\x");
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    Value::String(s)
}

/// Write `v` with keys sorted bytewise at every level, compact.
pub fn write_sorted(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                write_sorted(&map[k.as_str()], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_sorted(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn emit(w: &mut dyn Write, v: &Value) -> Result<()> {
    let mut s = String::new();
    write_sorted(v, &mut s);
    s.push('\n');
    w.write_all(s.as_bytes())
        .map_err(|e| StoreError::Io("<export>".into(), e))
}

/// Write one table as JSONL. `table` is one of [`EXPORT_TABLES`].
pub fn export_table(view: &ReadView<'_>, table: &str, w: &mut dyn Write) -> Result<()> {
    match table {
        "rpsl_objects" => {
            for item in view.objects(None, None)? {
                let (_, o) = item?;
                let parsed: Value = serde_json::from_str(o.parsed_data).unwrap_or(Value::Null);
                emit(
                    w,
                    &json!({
                        "pk": uuid(&o.pk),
                        "rpsl_pk": o.rpsl_pk,
                        "source": o.source,
                        "object_class": o.object_class,
                        "parsed_data": parsed,
                        "object_text": o.object_text,
                        "ip_version": o.ip_version,
                        "ip_first": o.ip_first.map(|a| InetDisplay(&a).to_string()),
                        "ip_last": o.ip_last.map(|a| InetDisplay(&a).to_string()),
                        "ip_size": o.ip_size(),
                        "prefix_length": o.prefix_length,
                        "prefix": o.prefix.map(|p| p.to_string()),
                        "asn_first": o.asn_first,
                        "asn_last": o.asn_last,
                        "rpki_status": o.rpki_status.pg_label(),
                        "scopefilter_status": o.scopefilter_status.pg_label(),
                        "route_preference_status": o.route_preference_status.pg_label(),
                        "created": ts(o.created),
                        "updated": ts(o.updated),
                    }),
                )?;
            }
        }
        "rpsl_database_journal" => {
            for item in view.journal(None, None, None)? {
                let e = item?;
                emit(
                    w,
                    &json!({
                        "pk": uuid(&e.pk),
                        "serial_global": e.serial_global,
                        "rpsl_pk": e.rpsl_pk,
                        "source": e.source,
                        "origin": e.origin.pg_label(),
                        "serial_nrtm": e.serial_nrtm,
                        "operation": e.operation.pg_label(),
                        "object_class": e.object_class,
                        "object_text": e.object_text,
                        "timestamp": ts(e.timestamp),
                    }),
                )?;
            }
        }
        "database_status" => {
            for s in view.database_statuses()? {
                emit(
                    w,
                    &json!({
                        "pk": uuid(&s.pk),
                        "source": s.source,
                        "serial_oldest_seen": s.serial_oldest_seen,
                        "serial_newest_seen": s.serial_newest_seen,
                        "serial_oldest_journal": s.serial_oldest_journal,
                        "serial_newest_journal": s.serial_newest_journal,
                        "serial_last_export": s.serial_last_export,
                        "serial_newest_mirror": s.serial_newest_mirror,
                        "nrtm4_client_session_id": ouuid(&s.nrtm4_client_session_id),
                        "nrtm4_client_version": s.nrtm4_client_version,
                        "nrtm4_client_current_key": s.nrtm4_client_current_key,
                        "nrtm4_client_next_key": s.nrtm4_client_next_key,
                        "nrtm4_client_previous_file_hashes": ojson(&s.nrtm4_client_previous_file_hashes),
                        "nrtm4_server_session_id": ouuid(&s.nrtm4_server_session_id),
                        "nrtm4_server_version": s.nrtm4_server_version,
                        "nrtm4_server_last_update_notification_file_update":
                            ots(s.nrtm4_server_last_update_notification_file_update),
                        "nrtm4_server_last_snapshot_version": s.nrtm4_server_last_snapshot_version,
                        "nrtm4_server_last_snapshot_global_serial": s.nrtm4_server_last_snapshot_global_serial,
                        "nrtm4_server_last_snapshot_timestamp": ots(s.nrtm4_server_last_snapshot_timestamp),
                        "nrtm4_server_last_snapshot_filename": s.nrtm4_server_last_snapshot_filename,
                        "nrtm4_server_last_snapshot_hash": s.nrtm4_server_last_snapshot_hash,
                        "nrtm4_server_previous_deltas": ojson(&s.nrtm4_server_previous_deltas),
                        "force_reload": s.force_reload,
                        "synchronised_serials": s.synchronised_serials,
                        "last_error": s.last_error,
                        "last_error_timestamp": ots(s.last_error_timestamp),
                        "rpsl_data_updated": ts(s.rpsl_data_updated),
                        "created": ts(s.created),
                        "updated": ts(s.updated),
                    }),
                )?;
            }
        }
        "roa_object" => {
            for r in view.roas()? {
                emit(
                    w,
                    &json!({
                        "pk": uuid(&r.pk),
                        "prefix": r.prefix.to_string(),
                        "asn": r.asn,
                        "max_length": r.max_length,
                        "trust_anchor": r.trust_anchor,
                        "ip_version": r.ip_version,
                        "created": ts(r.created),
                    }),
                )?;
            }
        }
        "rpsl_objects_suspended" => {
            let mut rows = view.suspended_objects()?;
            rows.sort_by(|a, b| {
                (&a.source, &a.object_class, &a.rpsl_pk, a.timestamp, a.pk).cmp(&(
                    &b.source,
                    &b.object_class,
                    &b.rpsl_pk,
                    b.timestamp,
                    b.pk,
                ))
            });
            for r in rows {
                emit(
                    w,
                    &json!({
                        "pk": uuid(&r.pk),
                        "rpsl_pk": r.rpsl_pk,
                        "source": r.source,
                        "object_class": r.object_class,
                        "object_text": r.object_text,
                        "mntners": r.mntners,
                        "timestamp": ts(r.timestamp),
                        "original_created": ts(r.original_created),
                        "original_updated": ts(r.original_updated),
                    }),
                )?;
            }
        }
        "protected_rpsl_name" => {
            let mut rows = view.protected_names()?;
            rows.sort_by(|a, b| {
                (
                    &a.source,
                    &a.protected_name,
                    &a.object_class,
                    &a.rpsl_pk,
                    a.created,
                    a.pk,
                )
                    .cmp(&(
                        &b.source,
                        &b.protected_name,
                        &b.object_class,
                        &b.rpsl_pk,
                        b.created,
                        b.pk,
                    ))
            });
            for r in rows {
                emit(
                    w,
                    &json!({
                        "pk": uuid(&r.pk),
                        "rpsl_pk": r.rpsl_pk,
                        "source": r.source,
                        "object_class": r.object_class,
                        "protected_name": r.protected_name,
                        "created": ts(r.created),
                    }),
                )?;
            }
        }
        "setting" => {
            for r in view.settings()? {
                emit(
                    w,
                    &json!({"name": r.name, "value": r.value, "created": ts(r.created)}),
                )?;
            }
        }
        "auth_user" => {
            for r in view.auth_users()? {
                emit(
                    w,
                    &json!({
                        "pk": uuid(&r.pk),
                        "email": r.email,
                        "name": r.name,
                        "password": r.password,
                        "totp_secret": r.totp_secret,
                        "totp_last_used": r.totp_last_used,
                        "active": r.active,
                        "override": r.override_,
                        "created": ts(r.created),
                        "updated": ts(r.updated),
                    }),
                )?;
            }
        }
        "auth_permission" => {
            for r in view.auth_permissions()? {
                emit(
                    w,
                    &json!({
                        "pk": uuid(&r.pk),
                        "user_id": ouuid(&r.user_id),
                        "mntner_id": ouuid(&r.mntner_id),
                        "user_management": r.user_management,
                        "created": ts(r.created),
                        "updated": ts(r.updated),
                    }),
                )?;
            }
        }
        "auth_mntner" => {
            for r in view.auth_mntners()? {
                emit(
                    w,
                    &json!({
                        "pk": uuid(&r.pk),
                        "rpsl_mntner_pk": r.rpsl_mntner_pk,
                        "rpsl_mntner_obj_id": uuid(&r.rpsl_mntner_obj_id),
                        "rpsl_mntner_source": r.rpsl_mntner_source,
                        "migration_token": r.migration_token,
                        "created": ts(r.created),
                        "updated": ts(r.updated),
                    }),
                )?;
            }
        }
        "auth_api_token" => {
            for r in view.auth_api_tokens()? {
                emit(
                    w,
                    &json!({
                        "pk": uuid(&r.pk),
                        "token": ouuid(&r.token),
                        "name": r.name,
                        "creator_id": ouuid(&r.creator_id),
                        "mntner_id": ouuid(&r.mntner_id),
                        "ip_restriction": r.ip_restriction,
                        "enabled_webapi": r.enabled_webapi,
                        "enabled_email": r.enabled_email,
                        "created": ts(r.created),
                        "updated": ts(r.updated),
                    }),
                )?;
            }
        }
        "auth_webauthn" => {
            for r in view.auth_webauthns()? {
                emit(
                    w,
                    &json!({
                        "pk": uuid(&r.pk),
                        "user_id": ouuid(&r.user_id),
                        "name": r.name,
                        "credential_id": bytea(&r.credential_id),
                        "credential_public_key": bytea(&r.credential_public_key),
                        "credential_sign_count": r.credential_sign_count,
                        "created": ts(r.created),
                        "last_used": ts(r.last_used),
                    }),
                )?;
            }
        }
        "change_log" => {
            for r in view.change_logs()? {
                emit(
                    w,
                    &json!({
                        "pk": uuid(&r.pk),
                        "auth_by_user_id": ouuid(&r.auth_by_user_id),
                        "auth_by_user_email": r.auth_by_user_email,
                        "auth_by_api_key_id": ouuid(&r.auth_by_api_key_id),
                        "auth_by_api_key_id_fixed": ouuid(&r.auth_by_api_key_id_fixed),
                        "auth_through_mntner_id": ouuid(&r.auth_through_mntner_id),
                        "auth_through_rpsl_mntner_pk": r.auth_through_rpsl_mntner_pk,
                        "auth_by_rpsl_mntner_password": r.auth_by_rpsl_mntner_password,
                        "auth_by_rpsl_mntner_pgp_key": r.auth_by_rpsl_mntner_pgp_key,
                        "auth_by_override": r.auth_by_override,
                        "from_email": r.from_email,
                        "from_ip": r.from_ip,
                        "auth_change_descr": r.auth_change_descr,
                        "auth_affected_user_id": ouuid(&r.auth_affected_user_id),
                        "auth_affected_mntner_id": ouuid(&r.auth_affected_mntner_id),
                        "rpsl_target_request_type": r.rpsl_target_request_type.map(|t| t.pg_label()),
                        "rpsl_target_pk": r.rpsl_target_pk,
                        "rpsl_target_source": r.rpsl_target_source,
                        "rpsl_target_object_class": r.rpsl_target_object_class,
                        "rpsl_target_object_text_old": r.rpsl_target_object_text_old,
                        "rpsl_target_object_text_new": r.rpsl_target_object_text_new,
                        "timestamp": ts(r.timestamp),
                    }),
                )?;
            }
        }
        other => {
            return Err(StoreError::ValueError(format!("unknown table {other}")));
        }
    }
    Ok(())
}
