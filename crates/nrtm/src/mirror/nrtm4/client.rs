//! `NRTM4Client` (`irrd/mirroring/nrtm4/nrtm4_client.py`).
//!
//! The Update Notification File is fetched and its signature checked
//! against the known keys; then either a snapshot is loaded (deltas wait
//! for the next run, v4 #1087) or the deltas since the local version are
//! applied. Everything is fetched and parsed first, then written in one
//! transaction with the new client status, so a failure anywhere changes
//! nothing, as v4's rollback does.

use std::sync::Arc;

use config::Value;
use store::{JournalEntryOrigin, Json, Nrtm4ClientStatus, Uuid};

use crate::file_import::Counters;
use crate::messages;
use crate::mirror::nrtm3::Operation;
use crate::mirror::nrtm4::json;
use crate::mirror::nrtm4::jsonseq::JsonSeqReader;
use crate::mirror::nrtm4::jws;
use crate::mirror::nrtm4::types::{self, HeaderKind, Unf};
use crate::mirror::operation::{self, NrtmOperation, OperationEnv, PreparedOperation};
use crate::mirror::pyerr::{PyErr, os_error};
use crate::mirror::retrieval::{LocalFile, Retriever};
use crate::mirror::runner::{
    ImportParser, MirrorContext, PARSE_BATCH, apply_operations, blocking, op_for,
};
use crate::mirror::settings::SourceMirrorSettings;
use crate::mirror::spool::{Spool, SpoolItem};

/// v4's logger name.
pub const LOG_TARGET: &str = "irrd.mirroring.nrtm4.nrtm4_client";

/// `run_client()`: inside it, a `ValueError` is an `NRTM4ClientError`.
fn client_error(e: PyErr) -> PyErr {
    match e {
        PyErr::Value(m) => PyErr::Nrtm4(m),
        other => other,
    }
}

/// `NRTM4ClientDatabaseStatus` as read from `database_status`.
#[derive(Debug, Clone, Default)]
pub struct LastStatus {
    /// `force_reload` (False without a status row).
    pub force_reload: bool,
    /// `nrtm4_client_session_id`
    pub session_id: Option<Uuid>,
    /// `nrtm4_client_version`
    pub version: Option<i64>,
    /// `nrtm4_client_current_key`
    pub current_key: Option<String>,
    /// `nrtm4_client_next_key`
    pub next_key: Option<String>,
    /// `nrtm4_client_previous_file_hashes`
    pub previous_file_hashes: Option<serde_json::Value>,
}

fn last_status(ctx: &MirrorContext, source: &str) -> Result<LastStatus, PyErr> {
    let r = ctx.store.read()?;
    Ok(match r.view().database_status(source)? {
        None => LastStatus::default(),
        Some(s) => LastStatus {
            force_reload: s.force_reload,
            session_id: s.nrtm4_client_session_id,
            version: s.nrtm4_client_version,
            current_key: s.nrtm4_client_current_key,
            next_key: s.nrtm4_client_next_key,
            previous_file_hashes: s
                .nrtm4_client_previous_file_hashes
                .and_then(|j| serde_json::from_str(j.as_str()).ok()),
        },
    })
}

/// `_deserialize_unf()`: the payload and the key (as configured or
/// stored) that verified it.
pub fn deserialize_unf(
    source: &str,
    unf_content: &str,
    last: &LastStatus,
    config_key: Option<&str>,
) -> Result<(Vec<u8>, String), PyErr> {
    let content = unf_content.as_bytes();
    let keys: Vec<Option<String>> = if last.current_key.is_some() {
        vec![last.current_key.clone(), last.next_key.clone()]
    } else {
        vec![config_key.map(str::to_owned)]
    };
    // A dict keyed on the key: one entry per distinct key.
    let mut errors: Vec<(String, String)> = Vec::new();
    for key in keys.into_iter().flatten() {
        if key.is_empty() {
            continue;
        }
        let pubkey = jws::eckey_from_str(&key).map_err(PyErr::Nrtm4)?;
        match jws::jws_deserialize(content, &pubkey) {
            Ok(payload) => return Ok((payload, key)),
            Err(e) => match errors.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = e,
                None => errors.push((key, e)),
            },
        }
    }
    if let Some(current) = &last.current_key {
        let verified = config_key
            .and_then(|k| jws::eckey_from_str(k).ok())
            .is_some_and(|k| jws::jws_deserialize(content, &k).is_ok());
        if verified {
            let msg_next_key = last
                .next_key
                .as_deref()
                .filter(|k| !k.is_empty())
                .map(messages::nrtm4_msg_next_key)
                .unwrap_or_default();
            return Err(PyErr::Nrtm4(messages::nrtm4_signature_config_key_only(
                source,
                config_key.unwrap_or_default(),
                current,
                &msg_next_key,
            )));
        }
    }
    let attempts: String = errors
        .iter()
        .map(|(k, e)| messages::nrtm4_key_attempt(&k.replace('\n', "\\n"), e))
        .collect();
    Err(PyErr::Nrtm4(messages::nrtm4_no_valid_signature(
        source, &attempts,
    )))
}

/// `_find_next_version(unf, last_version)`: `None` when a snapshot load
/// is needed.
pub fn find_next_version(
    source: &str,
    unf: &Unf,
    last: &LastStatus,
    last_version: Option<i64>,
) -> Result<Option<i64>, PyErr> {
    let lv = match last_version.filter(|v| *v != 0) {
        Some(v) => v,
        None => {
            if last.force_reload {
                tracing::info!(target: LOG_TARGET, "{}", messages::nrtm4_forced_reload(source));
                return Ok(None);
            }
            let (Some(sid), Some(v)) = (last.session_id, last.version.filter(|v| *v != 0)) else {
                tracing::info!(target: LOG_TARGET, "{}", messages::nrtm4_no_previous(source));
                return Ok(None);
            };
            if unf.session_id != sid {
                tracing::info!(
                    target: LOG_TARGET,
                    "{}",
                    messages::nrtm4_session_changed(source, &sid.to_string(), &unf.session_id.to_string())
                );
                return Ok(None);
            }
            v
        }
    };
    if lv > unf.version {
        return Err(PyErr::Nrtm4(messages::nrtm4_unf_older(
            source,
            &unf.session_id.to_string(),
            unf.version,
            lv,
        )));
    }
    let next = lv + 1;
    if let Some(min) = unf.min_delta_version()
        && min > next
    {
        tracing::info!(target: LOG_TARGET, "{}", messages::nrtm4_deltas_unavailable(source, lv));
        return Ok(None);
    }
    Ok(Some(next))
}

/// `_validate_aggregate_previous_file_hashes_from_unf()`: the new
/// `previous_file_hashes`, refusing a server that rewrites history.
///
/// File references are only unique within a session, so hashes stored
/// under another session are not compared (DIV-003). v4 compares them
/// anyway and, after a server session reset, fails every run with
/// "Server is rewriting history" for good.
pub fn aggregate_previous_file_hashes(
    source: &str,
    unf: &Unf,
    last: &LastStatus,
) -> Result<serde_json::Value, PyErr> {
    let mut current: Vec<(String, [String; 2])> = vec![(
        format!("snapshot-{}", unf.snapshot.version),
        [unf.snapshot.url.clone(), unf.snapshot.hash.clone()],
    )];
    for d in &unf.deltas {
        current.push((
            format!("delta-{}", d.version),
            [d.url.clone(), d.hash.clone()],
        ));
    }
    let as_json = |c: &[(String, [String; 2])]| {
        serde_json::Value::Object(
            c.iter()
                .map(|(k, v)| (k.clone(), serde_json::json!([v[0], v[1]])))
                .collect(),
        )
    };
    if last.session_id != Some(unf.session_id) {
        return Ok(as_json(&current));
    }
    let previous = match &last.previous_file_hashes {
        Some(serde_json::Value::Object(m)) if !m.is_empty() => m,
        _ => return Ok(as_json(&current)),
    };
    for (reference, details) in &current {
        if let Some(prev) = previous.get(reference) {
            let prev_parts: Vec<String> = match prev {
                serde_json::Value::Array(a) => a
                    .iter()
                    .map(|v| match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .collect(),
                other => vec![other.to_string()],
            };
            if prev_parts.as_slice() != details.as_slice() {
                return Err(PyErr::Nrtm4(messages::nrtm4_rewriting_history(
                    source,
                    reference,
                    &details[0],
                    &details[1],
                    prev_parts.first().map(String::as_str).unwrap_or_default(),
                    prev_parts.get(1).map(String::as_str).unwrap_or_default(),
                )));
            }
        }
    }
    Ok(as_json(&current))
}

/// A loaded snapshot, ready to write.
#[derive(Debug)]
struct SnapshotLoad {
    spool: Spool,
}

fn open(file: &LocalFile) -> Result<std::fs::File, PyErr> {
    std::fs::File::open(file.path()).map_err(|e| os_error(&e, Some(&file.name())))
}

/// `next(iterator)` on a JSON sequence.
fn next_item(r: &mut JsonSeqReader<std::fs::File>) -> Result<Option<Value>, PyErr> {
    match r.next_item() {
        None => Ok(None),
        Some(Ok(v)) => Ok(Some(v)),
        Some(Err(Ok(e))) => Err(PyErr::Nrtm4(e)),
        Some(Err(Err(e))) => Err(os_error(&e, None)),
    }
}

/// `item["key"]` on a JSON value, with Python's exceptions.
fn subscript<'a>(item: &'a Value, key: &str) -> Result<&'a Value, Result<String, PyErr>> {
    match item {
        Value::Dict(_) => json::get(item, key).ok_or_else(|| Ok(config::str_repr(key))),
        Value::List(_) => Err(Err(PyErr::Other(
            "list indices must be integers or slices, not str".into(),
        ))),
        Value::Str(_) => Err(Err(PyErr::Other(
            "string indices must be integers, not 'str'".into(),
        ))),
        other => Err(Err(PyErr::Other(format!(
            "'{}' object is not subscriptable",
            py_type(other)
        )))),
    }
}

fn py_type(v: &Value) -> &'static str {
    match v {
        Value::None => "NoneType",
        Value::Bool(_) => "bool",
        Value::Int(_) => "int",
        Value::Float(_) => "float",
        Value::Str(_) => "str",
        Value::List(_) => "list",
        Value::Dict(_) => "dict",
        _ => "object",
    }
}

fn as_text(v: &Value, method: &str) -> Result<String, PyErr> {
    match v {
        Value::Str(s) => Ok(s.clone()),
        other => Err(PyErr::Other(format!(
            "'{}' object has no attribute '{method}'",
            py_type(other)
        ))),
    }
}

/// `_load_snapshot(unf)`, minus the database writes.
async fn load_snapshot(
    ctx: &MirrorContext,
    src: &SourceMirrorSettings,
    unf: &Unf,
    url: &str,
    retriever: &Retriever,
) -> Result<SnapshotLoad, PyErr> {
    let snapshot_url = unf.snapshot.full_url(url);
    let file = retriever
        .file(&snapshot_url, Some(&unf.snapshot.hash))
        .await
        .map_err(client_error)?;
    let store = ctx.store.clone();
    let settings = ctx.settings.clone();
    let src = src.clone();
    let unf = unf.clone();
    blocking(move || {
        let mut reader = JsonSeqReader::new(open(&file)?);
        let header = next_item(&mut reader)?.ok_or_else(|| PyErr::Other(String::new()))?;
        types::validate_header(
            &header,
            HeaderKind::Snapshot,
            &src.name,
            &unf.session_id,
            unf.snapshot.version,
        )?;
        let parser = ImportParser::new(&store, &settings, &src)?;
        let mut spool = Spool::new()?;
        let mut counters = Counters::default();
        let mut batch: Vec<String> = Vec::with_capacity(PARSE_BATCH);
        loop {
            let item = next_item(&mut reader)?;
            if let Some(item) = &item {
                let text = match subscript(item, "object") {
                    Ok(v) => as_text(v, "strip")?,
                    Err(Ok(key)) => return Err(PyErr::Other(key)),
                    Err(Err(e)) => return Err(e),
                };
                batch.push(text);
            }
            if batch.len() >= PARSE_BATCH || (item.is_none() && !batch.is_empty()) {
                parser.parse_batch(&batch, &mut spool, &mut counters)?;
                batch.clear();
            }
            if item.is_none() {
                break;
            }
        }
        let prefix = messages::nrtm4_snapshot_prefix(&src.name, unf.snapshot.version);
        tracing::info!(
            target: crate::file_import::LOG_TARGET,
            "{}",
            messages::import_report(
                &prefix,
                counters.obj_parsed,
                counters.successful(),
                counters.obj_errors,
                counters.obj_ignored_class
            )
        );
        counters.log_unknown_object_classes(&src.name);
        spool.close()?;
        Ok(SnapshotLoad { spool })
    })
    .await
    .map_err(client_error)
}

/// `_load_deltas(unf, next_version)`, minus the database writes.
async fn load_deltas(
    ctx: &MirrorContext,
    src: &SourceMirrorSettings,
    unf: &Unf,
    url: &str,
    next_version: i64,
    retriever: &Retriever,
) -> Result<Vec<PreparedOperation>, PyErr> {
    let mut ops: Vec<PreparedOperation> = Vec::new();
    for delta in &unf.deltas {
        if delta.version < next_version {
            continue;
        }
        let delta_url = delta.full_url(url);
        let file = retriever
            .file(&delta_url, Some(&delta.hash))
            .await
            .map_err(client_error)?;
        let settings = ctx.settings.clone();
        let src = src.clone();
        let session_id = unf.session_id;
        let version = delta.version;
        let store = ctx.store.clone();
        let mut prepared = blocking(move || {
            let mut reader = JsonSeqReader::new(open(&file)?);
            let first = next_item(&mut reader)?.ok_or_else(|| PyErr::Other(String::new()))?;
            let header =
                types::validate_header(&first, HeaderKind::Delta, &src.name, &session_id, version)?;
            let keyring = crate::keyring::StoreKeyring::load(&store);
            let scopefilter = rpki::ScopeFilterValidator::new(settings.scopefilter.clone());
            let env = OperationEnv {
                rpsl: &settings.rpsl,
                keyring: &keyring,
                scopefilter: &scopefilter,
                rpki_excluded: src.rpki_excluded,
            };
            let mut out = Vec::new();
            let mut has_items = false;
            while let Some(item) = next_item(&mut reader)? {
                out.push(process_delta_item(&src, &settings, &header, &item, &env)?);
                has_items = true;
            }
            if !has_items {
                return Err(PyErr::Nrtm4(messages::nrtm4_empty_delta(
                    &src.name,
                    &session_id.to_string(),
                    version,
                )));
            }
            Ok(out)
        })
        .await
        .map_err(client_error)?;
        ops.append(&mut prepared);
    }
    Ok(ops)
}

/// `_process_delta_item()`.
fn process_delta_item(
    src: &SourceMirrorSettings,
    settings: &crate::mirror::settings::MirrorSettings,
    header: &types::Header,
    item: &Value,
    env: &OperationEnv<'_>,
) -> Result<PreparedOperation, PyErr> {
    let invalid = |ke: String| {
        PyErr::Nrtm4(messages::nrtm4_invalid_delta_entry(
            &src.name,
            &header.session_id.to_string(),
            header.version,
            &ke,
            &item.py_repr(),
        ))
    };
    let get = |key: &str| -> Result<&Value, PyErr> {
        match subscript(item, key) {
            Ok(v) => Ok(v),
            Err(Ok(ke)) => Err(invalid(ke)),
            Err(Err(e)) => Err(e),
        }
    };
    let action = get("action")?;
    let operation = match action {
        Value::Str(a) => op_for(a).ok_or_else(|| invalid(action.py_repr()))?,
        Value::List(_) | Value::Dict(_) => {
            return Err(PyErr::Other(format!(
                "unhashable type: '{}'",
                py_type(action)
            )));
        }
        other => return Err(invalid(other.py_repr())),
    };
    let mut op = NrtmOperation {
        source: src.name.clone(),
        operation,
        serial: None,
        origin_identifier: header.origin_identifier.clone(),
        object_text: None,
        rpsl_pk: None,
        object_class: None,
        strict_validation_key_cert: false,
        rpki_aware: settings.rpki_enabled,
        object_class_filter: src.object_class_filter.clone(),
    };
    match operation {
        Operation::Add => {
            let text = as_text(get("object")?, "strip")?;
            if text.is_empty() {
                return Err(PyErr::Other(messages::NRTM_OPERATION_TEXT_OR_PK.into()));
            }
            op.object_text = Some(text);
        }
        Operation::Del => {
            op.rpsl_pk = Some(as_text(get("primary_key")?, "upper")?.to_uppercase());
            op.object_class = Some(as_text(get("object_class")?, "lower")?.to_lowercase());
        }
    }
    operation::prepare(&op, env)
}

/// `NRTM4Client(source).run_client()`: `Ok(has_loaded_snapshot)`.
pub async fn run_client(ctx: &MirrorContext, src: &SourceMirrorSettings) -> Result<bool, PyErr> {
    let source = src.name.clone();
    let url = src
        .nrtm4_client_notification_file_url
        .clone()
        .unwrap_or_default();
    let last = last_status(ctx, &source)?;
    let retriever = Retriever::new(ctx.settings.download_timeout)?;

    // _retrieve_unf
    let unf_signed = retriever.contents(&url).await.map_err(client_error)?;
    let (payload, used_key) = deserialize_unf(
        &source,
        &unf_signed,
        &last,
        src.nrtm4_client_initial_public_key.as_deref(),
    )?;
    let unf = types::validate_unf(&payload, &source).map_err(client_error)?;

    let mut has_loaded_snapshot = false;
    let mut snapshot: Option<SnapshotLoad> = None;
    let mut next = find_next_version(&source, &unf, &last, None)?;
    if next.is_none() {
        snapshot = Some(load_snapshot(ctx, src, &unf, &url, &retriever).await?);
        has_loaded_snapshot = true;
        next = find_next_version(&source, &unf, &last, Some(unf.snapshot.version))?;
    }
    let deltas_deferred = has_loaded_snapshot;
    let mut delta_ops: Vec<PreparedOperation> = Vec::new();
    if deltas_deferred {
        tracing::info!(target: LOG_TARGET, "{}", messages::nrtm4_deferring_deltas(&source, unf.snapshot.version));
    } else if let (Some(max), Some(n)) = (unf.max_delta_version(), next)
        && n <= max
    {
        tracing::info!(target: LOG_TARGET, "{}", messages::nrtm4_updating_from_deltas(&source, n));
        delta_ops = load_deltas(ctx, src, &unf, &url, n, &retriever).await?;
    } else {
        tracing::info!(target: LOG_TARGET, "{}", messages::nrtm4_up_to_date(&source, unf.version));
    }

    if let Some(current) = &last.current_key
        && *current != used_key
    {
        tracing::info!(target: LOG_TARGET, "{}", messages::nrtm4_key_rotated(&source, current, &used_key));
    }
    let hashes = aggregate_previous_file_hashes(&source, &unf, &last)?;
    let new_status = Nrtm4ClientStatus {
        session_id: Some(unf.session_id),
        version: Some(if deltas_deferred {
            unf.snapshot.version
        } else {
            unf.version
        }),
        current_key: Some(used_key),
        next_key: unf.next_signing_key.clone(),
        previous_file_hashes: Some(Json::from_value(&hashes)),
    };

    match snapshot {
        None => {
            apply_operations(
                &ctx.store,
                &source,
                None,
                Arc::new(delta_ops),
                src.rpki_excluded,
                Some(new_status),
            )
            .await?;
        }
        Some(snap) => {
            let spool = Arc::new(snap.spool);
            let ops = Arc::new(delta_ops);
            let rpki_excluded = src.rpki_excluded;
            let reserve = spool.text_bytes.saturating_mul(5) + (1 << 20);
            let store = ctx.store.clone();
            blocking(move || {
                store
                    .write_reserving(reserve, move |tx| {
                        tx.delete_all_rpsl_objects_with_journal(&source, false)?;
                        tx.disable_journaling();
                        spool.for_each(&mut |item| match item {
                            SpoolItem::Upsert(o) => {
                                tx.upsert_rpsl_object(&o, JournalEntryOrigin::Mirror, None, None)
                            }
                            SpoolItem::MirrorError(e) => tx.record_mirror_error(&source, &e),
                        })?;
                        tx.enable_journaling();
                        for op in ops.iter() {
                            operation::apply(tx, op, rpki_excluded)?;
                        }
                        tx.record_nrtm4_client_status(&source, new_status.clone())?;
                        Ok(())
                    })
                    .map(|_| ())
                    .map_err(PyErr::from)
            })
            .await?;
        }
    }
    Ok(has_loaded_snapshot)
}
