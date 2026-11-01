//! `NRTM4Server` and `NRTM4ServerWriter`
//! (`irrd/mirroring/nrtm4/nrtm4_server.py`): snapshot, delta and Update
//! Notification File generation into `nrtm4_server_local_path`. v4 has no
//! NRTMv4 HTTP routes; an external web server publishes the directory.
//!
//! Each run follows v4 step by step: check the files the status names
//! still exist (or start a new session), write a delta with the journal
//! entries since the last one, commit the status with a fresh signed
//! Update Notification File, and every `nrtm4_server_snapshot_frequency`
//! write a new snapshot. Deltas expire after 24 hours, unreferenced
//! snapshots 24 hours after they were written.
//!
//! v4 serialises runs per source with two lock files in `piddir`; irrd-ng
//! runs every server in its own process, so the same two locks are
//! in-process mutexes, per source and repository directory. v4 reads the journal maximum, the delta and the
//! snapshot in one READ COMMITTED transaction, so a snapshot can include
//! changes after `last_snapshot_global_serial` (sent again in the next
//! delta). irrd-ng reads all three from one LMDB snapshot, which gives the
//! same files whenever nothing is written during the run.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

use serde_json::{Map, Value, json};
use store::{Json, Nrtm4ServerStatus, ReadTx, Store, Timestamp};
use uuid::Uuid;

use crate::messages;
use crate::mirror::pyerr::os_error_text;
use crate::mirror::settings::SourceMirrorSettings;
use crate::serve::export::{served_text, visible_ids_in_v4_order};
use crate::serve::{files, keys, ujson};

/// v4's logger name.
pub const LOG_TARGET: &str = "irrd.mirroring.nrtm4.nrtm4_server";

/// The scheduler's name for the runner.
pub const NRTM4_SERVER_RUNNER: &str = "NRTM4Server";

/// `UPDATE_NOTIFICATION_FILENAME`
pub const UPDATE_NOTIFICATION_FILENAME: &str = "update-notification-file.jose";

/// `NRTM4_SERVER_DELTA_EXPIRY_TIME`, in microseconds.
pub const DELTA_EXPIRY_MICROS: i64 = 24 * 3600 * 1_000_000;

/// `DANGLING_SNAPSHOT_EXPIRY_TIME`, in microseconds.
const DANGLING_SNAPSHOT_EXPIRY_MICROS: i64 = 24 * 3600 * 1_000_000;

const RS: u8 = 0x1e;

/// The status and snapshot locks of one source.
#[derive(Debug, Default)]
struct Locks {
    status: Mutex<()>,
    snapshot: Mutex<()>,
}

static LOCKS: LazyLock<Mutex<HashMap<String, Arc<Locks>>>> = LazyLock::new(Default::default);

fn locks_for(source: &str) -> Arc<Locks> {
    let mut map = LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    map.entry(source.to_owned()).or_default().clone()
}

fn try_lock(m: &Mutex<()>) -> Option<MutexGuard<'_, ()>> {
    match m.try_lock() {
        Ok(g) => Some(g),
        Err(std::sync::TryLockError::Poisoned(p)) => Some(p.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}

/// `NRTM4ServerDatabaseStatus`, with `previous_deltas` as JSON values.
#[derive(Debug, Clone, PartialEq)]
struct Status {
    session_id: Option<Uuid>,
    version: Option<i64>,
    last_update_notification_file_update: Option<Timestamp>,
    last_snapshot_version: Option<i64>,
    last_snapshot_global_serial: Option<i64>,
    last_snapshot_filename: Option<String>,
    last_snapshot_timestamp: Option<Timestamp>,
    last_snapshot_hash: Option<String>,
    previous_deltas: Vec<Value>,
}

impl Status {
    fn from_row(row: &store::DatabaseStatus) -> Status {
        let previous_deltas = match row.nrtm4_server_previous_deltas.as_ref().map(Json::value) {
            Some(Value::Array(a)) => a,
            _ => Vec::new(),
        };
        Status {
            session_id: row.nrtm4_server_session_id,
            version: row.nrtm4_server_version,
            last_update_notification_file_update: row
                .nrtm4_server_last_update_notification_file_update,
            last_snapshot_version: row.nrtm4_server_last_snapshot_version,
            last_snapshot_global_serial: row.nrtm4_server_last_snapshot_global_serial,
            last_snapshot_filename: row.nrtm4_server_last_snapshot_filename.clone(),
            last_snapshot_timestamp: row.nrtm4_server_last_snapshot_timestamp,
            last_snapshot_hash: row.nrtm4_server_last_snapshot_hash.clone(),
            previous_deltas,
        }
    }

    fn to_store(&self) -> Nrtm4ServerStatus {
        Nrtm4ServerStatus {
            session_id: self.session_id,
            version: self.version,
            last_update_notification_file_update: self.last_update_notification_file_update,
            last_snapshot_version: self.last_snapshot_version,
            last_snapshot_global_serial: self.last_snapshot_global_serial,
            last_snapshot_filename: self.last_snapshot_filename.clone(),
            last_snapshot_timestamp: self.last_snapshot_timestamp,
            last_snapshot_hash: self.last_snapshot_hash.clone(),
            previous_deltas: Some(Json::from_value(&Value::Array(
                self.previous_deltas.clone(),
            ))),
        }
    }
}

/// A Python exception's `str()`.
type PyResult<T> = Result<T, String>;

fn store_err(e: store::StoreError) -> String {
    e.to_string()
}

/// `delta[key]` as an integer.
fn delta_int(d: &Value, key: &str) -> PyResult<i64> {
    d.get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("'{key}'"))
}

fn delta_str<'v>(d: &'v Value, key: &str) -> PyResult<&'v str> {
    d.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("'{key}'"))
}

/// `str()` of a JSON value as Python prints it in an f-string.
fn py_str(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => "None".to_owned(),
        Some(other) => other.to_string(),
    }
}

/// pydantic's JSON form of an aware UTC `datetime`.
pub fn pydantic_utc(t: Timestamp) -> String {
    let secs = t.0.div_euclid(1_000_000);
    let micros = t.0.rem_euclid(1_000_000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let mut s = format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        sod / 3600,
        (sod / 60) % 60,
        sod % 60
    );
    if micros != 0 {
        s.push_str(&format!(".{micros:06}"));
    }
    s.push('Z');
    s
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `NRTM4Server(source).run()`.
pub fn run_nrtm4_server(store: &Store, settings: &SourceMirrorSettings) {
    if let Err(e) = run_writer(store, settings, Timestamp::now()) {
        tracing::error!(
            target: LOG_TARGET,
            "{}",
            messages::nrtm4_server_exception(&settings.name, &e)
        );
    }
}

/// One run at time `now`, for tests.
pub fn run_writer(store: &Store, settings: &SourceMirrorSettings, now: Timestamp) -> PyResult<()> {
    let Some(local_path) = settings.nrtm4_server_local_path.as_deref() else {
        return Err("expected str, bytes or os.PathLike object, not NoneType".to_owned());
    };
    let txn = store.read_long().map_err(store_err)?;
    let max_serial_global = txn
        .view()
        .max_serial_global()
        .map_err(store_err)?
        .unwrap_or(0);
    let mut w = Writer {
        store,
        settings,
        source: settings.name.clone(),
        path: PathBuf::from(local_path),
        path_str: files::py_path(local_path),
        timestamp: now,
        max_serial_global,
        txn,
        status: None,
        original_status: None,
        force_reload: false,
    };
    w.run()
}

struct Writer<'a> {
    store: &'a Store,
    settings: &'a SourceMirrorSettings,
    source: String,
    path: PathBuf,
    path_str: String,
    timestamp: Timestamp,
    max_serial_global: i64,
    /// The snapshot the journal and objects are read from.
    txn: ReadTx,
    status: Option<Status>,
    original_status: Option<Status>,
    force_reload: bool,
}

impl Writer<'_> {
    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn file_str(&self, name: &str) -> String {
        files::py_path_join(&self.path_str, name)
    }

    fn status(&mut self) -> PyResult<&mut Status> {
        self.status
            .as_mut()
            .ok_or_else(|| "'NoneType' object has no attribute 'session_id'".to_owned())
    }

    /// `_update_status()`: read the current status from the store.
    fn update_status(&mut self) -> PyResult<()> {
        self.status = None;
        self.original_status = None;
        let txn = self.store.read().map_err(store_err)?;
        let Some(row) = txn
            .view()
            .database_status(&self.source)
            .map_err(store_err)?
        else {
            tracing::debug!(target: LOG_TARGET, "{}", messages::nrtm4_server_no_status(&self.source));
            return Ok(());
        };
        self.force_reload = row.force_reload;
        let status = Status::from_row(&row);
        self.original_status = Some(status.clone());
        self.status = Some(status);
        Ok(())
    }

    fn run(&mut self) -> PyResult<()> {
        let locks = locks_for(&format!("{}\0{}", self.path_str, self.source));
        let Some(status_lock) = try_lock(&locks.status) else {
            tracing::debug!(target: LOG_TARGET, "{}", messages::nrtm4_server_locked(&self.source));
            return Ok(());
        };
        let mut status_lock = Some(status_lock);

        self.update_status()?;
        if self.status.is_none() {
            return Ok(());
        }
        if self.force_reload {
            tracing::debug!(target: LOG_TARGET, "{}", messages::nrtm4_server_force_reload(&self.source));
            return Ok(());
        }
        tracing::debug!(target: LOG_TARGET, "{}", messages::nrtm4_server_starting(&self.source, &self.path_str));

        if !self.verify_integrity()? {
            tracing::error!(target: LOG_TARGET, "{}", messages::nrtm4_server_integrity_failed(&self.source));
            self.status()?.session_id = None;
        }

        let is_initialisation = self.status()?.session_id.is_none();
        if is_initialisation {
            let session_id = Uuid::new_v4();
            let st = self.status()?;
            st.session_id = Some(session_id);
            st.version = Some(1);
            st.last_snapshot_version = None;
            st.last_snapshot_global_serial = None;
            st.previous_deltas = Vec::new();
            tracing::info!(
                target: LOG_TARGET,
                "{}",
                messages::nrtm4_server_new_session(&self.source, &session_id.to_string())
            );
        }

        if !is_initialisation {
            let st = self.status()?;
            let serial_global_start = match st.previous_deltas.last() {
                Some(d) => delta_int(d, "serial_global_end")?,
                None => st.last_snapshot_global_serial.ok_or_else(|| {
                    "unsupported operand type(s) for +=: 'NoneType' and 'int'".to_owned()
                })?,
            } + 1;
            let next_version = st.version.unwrap_or(0) + 1;
            if let Some(filename) = self.write_delta(next_version, serial_global_start)? {
                let hash = files::sha256_hex(&self.file(&filename))
                    .map_err(|e| os_error_text(&e, Some(&self.file_str(&filename))))?;
                let timestamp = self.timestamp.0 as f64 / 1_000_000.0;
                let max = self.max_serial_global;
                let st = self.status()?;
                st.version = Some(next_version);
                st.previous_deltas.push(json!({
                    "filename": filename,
                    "hash": hash,
                    "timestamp": timestamp,
                    "version": next_version,
                    "serial_global_start": serial_global_start,
                    "serial_global_end": max,
                }));
                tracing::info!(
                    target: LOG_TARGET,
                    "{}",
                    messages::nrtm4_server_created_delta(
                        &self.source,
                        next_version,
                        serial_global_start,
                        max,
                        &filename
                    )
                );
            }
            self.commit_status()?;
            status_lock = None;
        }

        let frequency = self
            .settings
            .nrtm4_server_snapshot_frequency
            .saturating_mul(1_000_000);
        let st = self.status()?;
        let should_create_snapshot = match st.last_snapshot_version {
            None | Some(0) => true,
            Some(v) => {
                let last = st.last_snapshot_timestamp.map_or(0, |t| t.0);
                Some(v) != st.version && self.timestamp.0 - last > frequency
            }
        };
        if !should_create_snapshot {
            return Ok(());
        }
        let Some(snapshot_lock) = try_lock(&locks.snapshot) else {
            tracing::debug!(target: LOG_TARGET, "{}", messages::nrtm4_server_snapshot_locked(&self.source));
            if status_lock.is_some() {
                self.commit_status()?;
            }
            return Ok(());
        };
        let snapshot_version = self.status()?.version.unwrap_or(1);
        tracing::debug!(
            target: LOG_TARGET,
            "{}",
            messages::nrtm4_server_generating_snapshot(&self.source, snapshot_version)
        );
        let snapshot_file = self.write_snapshot(snapshot_version)?;

        if !is_initialisation {
            status_lock = Some(locks.status.lock().unwrap_or_else(|e| e.into_inner()));
            self.update_status()?;
        }
        let hash = files::sha256_hex(&self.file(&snapshot_file))
            .map_err(|e| os_error_text(&e, Some(&self.file_str(&snapshot_file))))?;
        let (max, timestamp) = (self.max_serial_global, self.timestamp);
        let st = self.status()?;
        st.last_snapshot_filename = Some(snapshot_file.clone());
        st.last_snapshot_version = Some(snapshot_version);
        st.last_snapshot_global_serial = Some(max);
        st.last_snapshot_timestamp = Some(timestamp);
        st.last_snapshot_hash = Some(hash);
        tracing::info!(
            target: LOG_TARGET,
            "{}",
            messages::nrtm4_server_created_snapshot(&self.source, snapshot_version, max, &snapshot_file)
        );
        self.commit_status()?;
        drop(status_lock);
        drop(snapshot_lock);
        Ok(())
    }

    /// `_commit_status()`
    fn commit_status(&mut self) -> PyResult<()> {
        self.expire_deltas()?;
        self.write_unf()?;
        if self.status != self.original_status
            && let Some(st) = &self.status
        {
            let row = st.to_store();
            let source = self.source.clone();
            self.store
                .write(move |tx| tx.record_nrtm4_server_status(&source, row.clone()))
                .map_err(store_err)?;
        }
        self.expire_snapshots()
    }

    /// `_write_unf()`
    fn write_unf(&mut self) -> PyResult<()> {
        let next_key = match &self.settings.nrtm4_server_private_key_next {
            Some(pem) => Some(keys::public_key_pem(&keys::private_key_from_str(pem)?)),
            None => None,
        };
        let timestamp = self.timestamp;
        let source = self.source.clone();
        let st = self.status()?;
        let mut unf = Map::new();
        unf.insert("nrtm_version".into(), json!(4));
        unf.insert("source".into(), json!(source));
        unf.insert(
            "session_id".into(),
            json!(st.session_id.map(|s| s.to_string())),
        );
        unf.insert("version".into(), json!(st.version));
        unf.insert("timestamp".into(), json!(pydantic_utc(timestamp)));
        unf.insert("type".into(), json!("notification"));
        let mut snapshot = Map::new();
        snapshot.insert("version".into(), json!(st.last_snapshot_version));
        snapshot.insert("url".into(), json!(st.last_snapshot_filename));
        snapshot.insert("hash".into(), json!(st.last_snapshot_hash));
        snapshot.retain(|_, v| !v.is_null());
        unf.insert("snapshot".into(), Value::Object(snapshot));
        let mut deltas = Vec::new();
        for d in &st.previous_deltas {
            deltas.push(json!({
                "version": d.get("version"),
                "url": d.get("filename"),
                "hash": d.get("hash"),
            }));
        }
        unf.insert("deltas".into(), Value::Array(deltas));
        if let Some(k) = next_key {
            unf.insert("next_signing_key".into(), json!(k));
        }
        let content = pydantic_json(&unf);
        let key = match &self.settings.nrtm4_server_private_key {
            Some(pem) => keys::private_key_from_str(pem)?,
            None => return Err("'NoneType' object has no attribute 'is_private'".to_owned()),
        };
        let serialized = keys::jws_serialize(content.as_bytes(), &key);
        let path = self.file(UPDATE_NOTIFICATION_FILENAME);
        std::fs::write(&path, serialized)
            .map_err(|e| os_error_text(&e, Some(&self.file_str(UPDATE_NOTIFICATION_FILENAME))))?;
        self.status()?.last_update_notification_file_update = Some(timestamp);
        Ok(())
    }

    /// `_expire_deltas()`
    fn expire_deltas(&mut self) -> PyResult<()> {
        let now = self.timestamp.0;
        let deltas = std::mem::take(&mut self.status()?.previous_deltas);
        let mut kept = Vec::new();
        for d in deltas {
            let ts = d
                .get("timestamp")
                .and_then(Value::as_f64)
                .ok_or_else(|| "'timestamp'".to_owned())?;
            let micros = (ts * 1_000_000.0).round_ties_even() as i64;
            if now - micros > DELTA_EXPIRY_MICROS {
                let name = delta_str(&d, "filename")?.to_owned();
                std::fs::remove_file(self.file(&name))
                    .map_err(|e| os_error_text(&e, Some(&self.file_str(&name))))?;
                tracing::debug!(
                    target: LOG_TARGET,
                    "{}",
                    messages::nrtm4_server_expired_delta(&self.source, &py_str(d.get("version")))
                );
            } else {
                kept.push(d);
            }
        }
        let known: Vec<String> = kept
            .iter()
            .filter_map(|d| d.get("filename").and_then(Value::as_str).map(str::to_owned))
            .collect();
        self.status()?.previous_deltas = kept;
        for name in self.glob("nrtm-delta.", ".json.gz")? {
            if !known.contains(&name) {
                std::fs::remove_file(self.file(&name))
                    .map_err(|e| os_error_text(&e, Some(&self.file_str(&name))))?;
                tracing::debug!(
                    target: LOG_TARGET,
                    "{}",
                    messages::nrtm4_server_dangling_delta(&self.source, &name)
                );
            }
        }
        Ok(())
    }

    /// `_expire_snapshots()`
    fn expire_snapshots(&mut self) -> PyResult<()> {
        let now = self.timestamp.0;
        let current = self.status()?.last_snapshot_filename.clone();
        for name in self.glob("nrtm-snapshot.", ".json.gz")? {
            let path = self.file(&name);
            let modified = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .map_err(|e| os_error_text(&e, Some(&self.file_str(&name))))?;
            let mtime = modified
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_micros() as i64);
            if now - mtime > DANGLING_SNAPSHOT_EXPIRY_MICROS && Some(&name) != current.as_ref() {
                std::fs::remove_file(&path)
                    .map_err(|e| os_error_text(&e, Some(&self.file_str(&name))))?;
            }
        }
        Ok(())
    }

    /// `self.path.glob(f"{prefix}*{suffix}")`: names of files in the
    /// directory, sorted for a stable order.
    fn glob(&self, prefix: &str, suffix: &str) -> PyResult<Vec<String>> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.path) {
            Ok(e) => e,
            Err(_) => return Ok(out),
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.len() >= prefix.len() + suffix.len()
                && name.starts_with(prefix)
                && name.ends_with(suffix)
            {
                out.push(name);
            }
        }
        out.sort();
        Ok(out)
    }

    /// `_write_snapshot(version)`: returns the file name.
    fn write_snapshot(&mut self, version: i64) -> PyResult<String> {
        let session_id = self
            .status()?
            .session_id
            .map(|s| s.to_string())
            .unwrap_or_default();
        let filename = format!(
            "nrtm-snapshot.{session_id}.{version}.{}.json.gz",
            files::token_hex(16).map_err(|e| e.to_string())?
        );
        let path_str = self.file_str(&filename);
        let io = |e: std::io::Error| os_error_text(&e, Some(&path_str));
        let mut gz = files::PyGzipWriter::create(&self.file(&filename)).map_err(io)?;
        write_record(&mut gz, &self.header("snapshot", &session_id, version)).map_err(io)?;
        let view = self.txn.view();
        let ids = visible_ids_in_v4_order(&view, &self.source).map_err(store_err)?;
        let mut record = String::new();
        for id in ids {
            let Some(o) = view.object_by_id(id).map_err(store_err)? else {
                continue;
            };
            let text = served_text(
                o.object_text,
                o.object_class,
                o.rpsl_pk,
                self.settings,
                false,
            );
            record.clear();
            ujson::write_object(&mut record, &[("object", &ujson::string(&text))]);
            write_record(&mut gz, &record).map_err(io)?;
        }
        gz.finish().map_err(io)?;
        Ok(filename)
    }

    fn header(&self, kind: &str, session_id: &str, version: i64) -> String {
        let mut out = String::new();
        ujson::write_object(
            &mut out,
            &[
                ("nrtm_version", "4"),
                ("source", &ujson::string(&self.source)),
                ("session_id", &ujson::string(session_id)),
                ("version", &version.to_string()),
                ("type", &ujson::string(kind)),
            ],
        );
        out
    }

    /// `_write_delta(version, serial_global_start)`: the file name, or
    /// `None` when there are no journal entries to send.
    fn write_delta(&mut self, version: i64, serial_global_start: i64) -> PyResult<Option<String>> {
        let session_id = self
            .status()?
            .session_id
            .map(|s| s.to_string())
            .unwrap_or_default();
        let view = self.txn.view();
        let mut entries = Vec::new();
        for e in view
            .journal_by_serial_global(serial_global_start)
            .map_err(store_err)?
        {
            let e = e.map_err(store_err)?;
            if e.source == self.source {
                entries.push(e);
            }
        }
        if entries.is_empty() {
            return Ok(None);
        }
        // RPSLDatabaseJournalQuery orders by source, serial_nrtm.
        entries.sort_by_key(|e| e.serial_nrtm);
        let filename = format!(
            "nrtm-delta.{session_id}.{version}.{}.json.gz",
            files::token_hex(16).map_err(|e| e.to_string())?
        );
        let path_str = self.file_str(&filename);
        let io = |e: std::io::Error| os_error_text(&e, Some(&path_str));
        let mut gz = files::PyGzipWriter::create(&self.file(&filename)).map_err(io)?;
        write_record(&mut gz, &self.header("delta", &session_id, version)).map_err(io)?;
        let mut record = String::new();
        for e in &entries {
            record.clear();
            match e.operation {
                store::DatabaseOperation::AddOrUpdate => {
                    let text = served_text(
                        e.object_text,
                        e.object_class,
                        e.rpsl_pk,
                        self.settings,
                        false,
                    );
                    ujson::write_object(
                        &mut record,
                        &[
                            ("action", "\"add_modify\""),
                            ("object", &ujson::string(&text)),
                        ],
                    );
                }
                store::DatabaseOperation::Delete => {
                    ujson::write_object(
                        &mut record,
                        &[
                            ("action", "\"delete\""),
                            ("object_class", &ujson::string(e.object_class)),
                            ("primary_key", &ujson::string(e.rpsl_pk)),
                        ],
                    );
                }
            }
            write_record(&mut gz, &record).map_err(io)?;
        }
        gz.finish().map_err(io)?;
        Ok(Some(filename))
    }

    /// `_verify_integrity()`
    fn verify_integrity(&mut self) -> PyResult<bool> {
        let st = self.status()?;
        let mut names: Vec<String> = st
            .previous_deltas
            .iter()
            .map(|d| py_str(d.get("filename")))
            .collect();
        if let Some(s) = &st.last_snapshot_filename {
            names.push(s.clone());
        }
        for name in names {
            if !Path::new(&self.file(&name)).exists() {
                tracing::error!(
                    target: LOG_TARGET,
                    "{}",
                    messages::nrtm4_server_missing_file(&self.source, &name, &self.path_str)
                );
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// `jsonseq_encode_one`: RS, the JSON text, LF.
fn write_record(w: &mut impl std::io::Write, json_text: &str) -> std::io::Result<()> {
    w.write_all(&[RS])?;
    w.write_all(json_text.as_bytes())?;
    w.write_all(b"\n")
}

/// `model_dump_json()` of the Update Notification File: compact, fields
/// in model order, strings as pydantic-core writes them.
fn pydantic_json(unf: &Map<String, Value>) -> String {
    const ORDER: &[&str] = &[
        "nrtm_version",
        "source",
        "session_id",
        "version",
        "timestamp",
        "type",
        "snapshot",
        "deltas",
        "next_signing_key",
    ];
    const REF_ORDER: &[&str] = &["version", "url", "hash"];
    fn file_ref(v: &Value, out: &mut String) {
        out.push('{');
        let mut first = true;
        for k in REF_ORDER {
            if let Some(x) = v.get(*k).filter(|x| !x.is_null()) {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&Value::String((*k).to_owned()).to_string());
                out.push(':');
                out.push_str(&x.to_string());
            }
        }
        out.push('}');
    }
    let mut out = String::from("{");
    let mut first = true;
    for k in ORDER {
        let Some(v) = unf.get(*k) else { continue };
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&Value::String((*k).to_owned()).to_string());
        out.push(':');
        match *k {
            "snapshot" => file_ref(v, &mut out),
            "deltas" => {
                out.push('[');
                for (i, d) in v.as_array().into_iter().flatten().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    file_ref(d, &mut out);
                }
                out.push(']');
            }
            _ => out.push_str(&v.to_string()),
        }
    }
    out.push('}');
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn utc_like_pydantic() {
        // 2026-11-01T01:02:03.000456Z
        let t = Timestamp(1_793_494_923_000_456);
        assert_eq!(pydantic_utc(t), "2026-11-01T01:02:03.000456Z");
        assert_eq!(
            pydantic_utc(Timestamp(1_793_494_923_000_000)),
            "2026-11-01T01:02:03Z"
        );
    }

    /// The output of v4's `model_dump_json(exclude_none=True,
    /// include=unf.model_fields_set)`, recorded in the pinned image.
    #[test]
    fn unf_like_pydantic() {
        let mut unf = Map::new();
        unf.insert("nrtm_version".into(), json!(4));
        unf.insert("source".into(), json!("TEST"));
        unf.insert(
            "session_id".into(),
            json!("00000000-0000-0000-0000-000000000005"),
        );
        unf.insert("version".into(), json!(2));
        unf.insert("timestamp".into(), json!("2026-11-01T01:02:03.000456Z"));
        unf.insert("type".into(), json!("notification"));
        unf.insert(
            "snapshot".into(),
            json!({"version": 1, "url": "a", "hash": "b"}),
        );
        unf.insert(
            "deltas".into(),
            json!([{"version": 2, "url": "c", "hash": "d"}]),
        );
        assert_eq!(
            pydantic_json(&unf),
            r#"{"nrtm_version":4,"source":"TEST","session_id":"00000000-0000-0000-0000-000000000005","version":2,"timestamp":"2026-11-01T01:02:03.000456Z","type":"notification","snapshot":{"version":1,"url":"a","hash":"b"},"deltas":[{"version":2,"url":"c","hash":"d"}]}"#
        );
        unf.insert("deltas".into(), json!([]));
        unf.insert(
            "next_signing_key".into(),
            json!("-----BEGIN PUBLIC KEY-----\nX\n"),
        );
        assert!(
            pydantic_json(&unf)
                .ends_with(r#""deltas":[],"next_signing_key":"-----BEGIN PUBLIC KEY-----\nX\n"}"#)
        );
    }
}
