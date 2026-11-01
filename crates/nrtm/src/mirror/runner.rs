//! `irrd/mirroring/mirror_runners_import.py`: `RPSLMirrorImportUpdateRunner`
//! and the full import and NRTMv3 runners it calls.
//!
//! v4 runs one database transaction per run and commits it at the end, so
//! a failure anywhere leaves the database as it was (including any mirror
//! error recorded on the way). irrd-ng does the same: all network I/O and
//! all parsing happen first, then one write transaction applies the result.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rpki::{BulkRouteRoaValidator, ScopeFilterValidator};
use store::{JournalEntryOrigin, Store, StoreError};

use crate::file_import::{self, Counters, ImportSettings, ParseEnv, StreamError};
use crate::messages;
use crate::mirror::nrtm3::{self, Operation};
use crate::mirror::operation::{self, NrtmOperation, OperationEnv, PreparedOperation};
use crate::mirror::pyerr::{PyErr, os_error};
use crate::mirror::retrieval::{LocalFile, Retriever};
use crate::mirror::settings::{MirrorSettings, SourceMirrorSettings};
use crate::mirror::spool::{ParagraphReader, Spool, SpoolItem};

/// v4's logger name.
pub const LOG_TARGET: &str = "irrd.mirroring.mirror_runners_import";

/// Paragraphs parsed per batch: bounds memory on large files.
pub(crate) const PARSE_BATCH: usize = 1 << 16;

/// What a mirror run needs.
#[derive(Debug, Clone)]
pub struct MirrorContext {
    /// The store.
    pub store: Store,
    /// The settings in force when the run started.
    pub settings: Arc<MirrorSettings>,
}

/// Python's `repr()` of an optional integer.
fn repr_opt_int(v: Option<i64>) -> String {
    v.map_or_else(|| "None".to_owned(), |n| n.to_string())
}

fn repr_opt_bool(v: Option<bool>) -> String {
    match v {
        None => "None".into(),
        Some(true) => "True".into(),
        Some(false) => "False".into(),
    }
}

/// Run a blocking closure off the async runtime.
pub(crate) async fn blocking<T, F>(f: F) -> Result<T, PyErr>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, PyErr> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) => Err(PyErr::Other(e.to_string())),
    }
}

/// Add one batch's counters to the total, keeping first-seen order of
/// unknown classes.
pub(crate) fn merge_counters(total: &mut Counters, c: Counters) {
    total.obj_parsed += c.obj_parsed;
    total.obj_errors += c.obj_errors;
    total.obj_ignored_class += c.obj_ignored_class;
    total.obj_unknown += c.obj_unknown;
    for class in c.unknown_object_classes {
        if !total.unknown_object_classes.contains(&class) {
            total.unknown_object_classes.push(class);
        }
    }
}

/// The parser state for one import: settings, keyring and validators.
pub(crate) struct ImportParser {
    pub(crate) import: ImportSettings,
    pub(crate) rpsl: rpsl::RpslSettings,
    pub(crate) keyring: crate::keyring::StoreKeyring,
    pub(crate) roa: Option<BulkRouteRoaValidator>,
    pub(crate) scopefilter: ScopeFilterValidator,
}

impl ImportParser {
    /// `MirrorFileImportParserBase.__init__` for a source; the bulk ROA
    /// validator is built from the store when RPKI is enabled.
    pub(crate) fn new(
        store: &Store,
        settings: &MirrorSettings,
        src: &SourceMirrorSettings,
    ) -> Result<ImportParser, PyErr> {
        let roa = if settings.rpki_enabled {
            let r = store.read()?;
            Some(BulkRouteRoaValidator::from_store(
                &r.view(),
                settings.rpki_excluded_sources.clone(),
            )?)
        } else {
            None
        };
        Ok(ImportParser {
            import: ImportSettings {
                source: src.name.clone(),
                object_class_filter: src.object_class_filter.clone(),
                strict_import_keycert_objects: src.strict_import_keycert_objects,
                direct_error_return: false,
                keep_plain_text: false,
            },
            rpsl: settings.rpsl.clone(),
            keyring: crate::keyring::StoreKeyring::load(store),
            roa,
            scopefilter: ScopeFilterValidator::new(settings.scopefilter.clone()),
        })
    }

    /// `parse_object()` on a batch of texts, spooling the results.
    pub(crate) fn parse_batch(
        &self,
        texts: &[String],
        spool: &mut Spool,
        total: &mut Counters,
    ) -> Result<(), PyErr> {
        let env = ParseEnv {
            rpsl: &self.rpsl,
            keyring: &self.keyring,
            roa_validator: self.roa.as_ref(),
            scopefilter: &self.scopefilter,
        };
        let failed: Mutex<Option<PyErr>> = Mutex::new(None);
        let c = file_import::parse_streaming(texts, &self.import, &env, &mut |a| {
            spool.push_action(a).map_err(|e| {
                let msg = e.message().to_owned();
                if let Ok(mut f) = failed.lock() {
                    *f = Some(e);
                }
                StoreError::Aborted(msg)
            })
        });
        match c {
            Ok(c) => {
                merge_counters(total, c);
                Ok(())
            }
            Err(StreamError::Import(file_import::ImportError::Uncaught(m)))
            | Err(StreamError::Import(file_import::ImportError::Rpsl(m))) => Err(PyErr::Other(m)),
            Err(StreamError::Store(e)) => Err(failed
                .lock()
                .ok()
                .and_then(|mut f| f.take())
                .unwrap_or_else(|| PyErr::Other(e.to_string()))),
        }
    }
}

/// `RPSLMirrorImportUpdateRunner(source).run()`: one update of one mirror,
/// logging any failure as v4 does.
pub async fn run_mirror_update(ctx: MirrorContext, source: String) {
    let result = run(&ctx, &source).await;
    match result {
        Ok(full_reload) => {
            if full_reload {
                ctx.store.publish_event(&source, "full_reload");
            }
        }
        Err(PyErr::Nrtm4(m)) => {
            tracing::error!(target: LOG_TARGET, "{}", messages::nrtm4_validation_errors(&source, &m));
        }
        Err(PyErr::Os(m)) => {
            tracing::error!(target: LOG_TARGET, "{}", messages::mirror_os_error(&source, &m));
        }
        Err(PyErr::Value(m)) | Err(PyErr::Other(m)) => {
            tracing::error!(target: LOG_TARGET, "{}", messages::mirror_exception(&source, &m));
        }
    }
}

/// The run itself: `Ok(full_reload)`.
pub async fn run(ctx: &MirrorContext, source: &str) -> Result<bool, PyErr> {
    let src = ctx.settings.source(source);
    if src.nrtm4_client_notification_file_url.is_some() {
        return crate::mirror::nrtm4::client::run_client(ctx, &src).await;
    }
    run_full_or_nrtm3_import(ctx, &src).await
}

/// `_status()`: `(serial_newest_mirror, force_reload)`, both `None`
/// without a status row.
fn status(store: &Store, source: &str) -> Result<(Option<i64>, Option<bool>), PyErr> {
    let r = store.read()?;
    Ok(match r.view().database_status(source)? {
        Some(s) => (s.serial_newest_mirror, Some(s.force_reload)),
        None => (None, None),
    })
}

async fn run_full_or_nrtm3_import(
    ctx: &MirrorContext,
    src: &SourceMirrorSettings,
) -> Result<bool, PyErr> {
    let (serial_newest_mirror, force_reload) = status(&ctx.store, &src.name)?;
    let nrtm_enabled = src.nrtm_host.is_some();
    tracing::debug!(
        target: LOG_TARGET,
        "{}",
        messages::mirror_status(
            &src.name,
            &repr_opt_int(serial_newest_mirror),
            &repr_opt_bool(force_reload),
            &repr_opt_bool(Some(nrtm_enabled)),
        )
    );
    let full_reload =
        force_reload == Some(true) || serial_newest_mirror.is_none_or(|s| s == 0) || !nrtm_enabled;
    if full_reload {
        run_full_import(ctx, src, serial_newest_mirror, force_reload == Some(true)).await?;
    } else if let Some(serial) = serial_newest_mirror {
        run_nrtm3(ctx, src, serial).await?;
    }
    Ok(full_reload)
}

/// `RPSLMirrorFullImportRunner.run()`.
pub async fn run_full_import(
    ctx: &MirrorContext,
    src: &SourceMirrorSettings,
    serial_newest_mirror: Option<i64>,
    force_reload: bool,
) -> Result<(), PyErr> {
    let source = src.name.clone();
    let Some(import_sources) = src.import_source.clone() else {
        tracing::info!(target: LOG_TARGET, "{}", messages::skipping_full_import(&source));
        return Ok(());
    };
    tracing::info!(
        target: LOG_TARGET,
        "{}",
        messages::running_full_import(&source, &src.import_source_repr, &src.import_serial_source_str)
    );
    let retriever = Retriever::new(ctx.settings.download_timeout)?;
    let mut import_serial = None;
    if let Some(url) = &src.import_serial_source {
        let serial = crate::mirror::pyerr::py_int(&retriever.contents(url).await?)?;
        import_serial = Some(serial);
        if !force_reload
            && let Some(newest) = serial_newest_mirror
            && serial <= newest
        {
            tracing::info!(target: LOG_TARGET, "{}", messages::full_import_cancelled(&source, newest, serial));
            return Ok(());
        }
    }
    let mut files: Vec<LocalFile> = Vec::new();
    for url in &import_sources {
        files.push(retriever.file(url, None).await?);
    }

    let store = ctx.store.clone();
    let settings = ctx.settings.clone();
    let src2 = src.clone();
    let spool = blocking(move || {
        let parser = ImportParser::new(&store, &settings, &src2)?;
        let mut spool = Spool::new()?;
        for file in &files {
            let name = file.name();
            tracing::debug!(target: file_import::LOG_TARGET, "{}", messages::starting_file_import(&src2.name, &name));
            let f = std::fs::File::open(file.path()).map_err(|e| os_error(&e, Some(&name)))?;
            let mut reader = ParagraphReader::new(f);
            let mut counters = Counters::default();
            loop {
                let batch = reader
                    .next_chunk(PARSE_BATCH)
                    .map_err(|e| os_error(&e, Some(&name)))?;
                if batch.is_empty() {
                    break;
                }
                parser.parse_batch(&batch, &mut spool, &mut counters)?;
            }
            file_import::log_file_import_report(&src2.name, &counters);
        }
        drop(files);
        spool.close()?;
        // Rows are written in the store's key order, as
        // irrd_load_database does; journaling is off, so only the store's
        // layout depends on the order.
        spool.sort_by_key();
        Ok(spool)
    })
    .await?;

    let spool = Arc::new(spool);
    let reserve = spool.text_bytes.saturating_mul(5) + (1 << 20);
    let store = ctx.store.clone();
    blocking(move || {
        store
            .write_reserving(reserve, move |tx| {
                tx.delete_all_rpsl_objects_with_journal(&source, false)?;
                tx.disable_journaling();
                spool.for_each_sorted(&mut |item| match item {
                    SpoolItem::Upsert(o) => {
                        tx.upsert_rpsl_object(&o, JournalEntryOrigin::Mirror, None, None)
                    }
                    SpoolItem::MirrorError(e) => tx.record_mirror_error(&source, &e),
                })?;
                if let Some(s) = import_serial
                    && s != 0
                {
                    tx.record_serial_newest_mirror(&source, s)?;
                }
                Ok(())
            })
            .map(|_| ())
            .map_err(PyErr::from)
    })
    .await
}

/// The end markings `NRTMImportUpdateStreamRunner` reads up to.
pub fn nrtm3_end_markings(source: &str) -> Vec<String> {
    vec![
        format!("\n%END {source}\n"),
        format!("\n% END {source}\n"),
        "\n%ERROR".to_owned(),
        "\n% ERROR".to_owned(),
        "\n% Warning: there are no newer updates available".to_owned(),
        "\n% Warning (1): there are no newer updates available".to_owned(),
    ]
}

/// `NRTMImportUpdateStreamRunner.run(serial_newest_mirror)`.
pub async fn run_nrtm3(
    ctx: &MirrorContext,
    src: &SourceMirrorSettings,
    serial_newest_mirror: i64,
) -> Result<(), PyErr> {
    let source = src.name.clone();
    let serial_start = serial_newest_mirror
        .checked_add(1)
        .ok_or_else(|| PyErr::Other(messages::BIGINT_OUT_OF_RANGE.into()))?;
    let Some(host) = src.nrtm_host.clone() else {
        tracing::debug!(target: LOG_TARGET, "{}", messages::skipping_nrtm(&source));
        return Ok(());
    };
    let port = src.nrtm_port.clone().map_err(PyErr::Value)?;
    let timeout = src.nrtm3_client_timeout.clone().map_err(PyErr::Value)?;
    tracing::info!(target: LOG_TARGET, "{}", messages::retrieving_nrtm(&source, serial_start, &host, port));
    let query = format!("-g {source}:3:{serial_start}-LAST");
    let port16 = u16::try_from(port).map_err(|_| PyErr::Other(messages::PORT_RANGE.into()))?;
    let response = crate::mirror::net::whois_query(
        &host,
        port16,
        &query,
        &nrtm3_end_markings(&source),
        Duration::from_secs(timeout.max(0) as u64),
    )
    .await?;
    tracing::debug!(target: LOG_TARGET, "{}", messages::received_nrtm(&source, rpsl::text::py_strip(&response)));

    let settings = ctx.settings.clone();
    let src2 = src.clone();
    let store = ctx.store.clone();
    let (last_serial, ops) = blocking(move || {
        let stream = nrtm3::parse_nrtm_stream(&src2.name, &response)?;
        let keyring = crate::keyring::StoreKeyring::load(&store);
        let scopefilter = ScopeFilterValidator::new(settings.scopefilter.clone());
        let env = OperationEnv {
            rpsl: &settings.rpsl,
            keyring: &keyring,
            scopefilter: &scopefilter,
            rpki_excluded: src2.rpki_excluded,
        };
        let mut ops = Vec::with_capacity(stream.operations.len());
        for o in stream.operations {
            let op = NrtmOperation {
                source: src2.name.clone(),
                operation: o.operation,
                serial: Some(o.serial),
                origin_identifier: o.serial.to_string(),
                object_text: Some(o.object_text),
                rpsl_pk: None,
                object_class: None,
                strict_validation_key_cert: src2.strict_import_keycert_objects,
                rpki_aware: settings.rpki_enabled,
                object_class_filter: src2.object_class_filter.clone(),
            };
            ops.push(operation::prepare(&op, &env)?);
        }
        Ok((stream.last_serial, ops))
    })
    .await?;
    apply_operations(
        &ctx.store,
        &source,
        Some(last_serial),
        Arc::new(ops),
        src.rpki_excluded,
        None,
    )
    .await
}

/// Apply NRTM operations in one transaction, recording the newest mirror
/// serial (NRTMv3) and the NRTMv4 client status, if given.
pub(crate) async fn apply_operations(
    store: &Store,
    source: &str,
    last_serial: Option<i64>,
    ops: Arc<Vec<PreparedOperation>>,
    rpki_excluded: bool,
    nrtm4_status: Option<store::Nrtm4ClientStatus>,
) -> Result<(), PyErr> {
    let store = store.clone();
    let source = source.to_owned();
    blocking(move || {
        store
            .write(move |tx| {
                if let Some(s) = last_serial
                    && s > 0
                {
                    tx.record_serial_newest_mirror(&source, s)?;
                }
                for op in ops.iter() {
                    operation::apply(tx, op, rpki_excluded)?;
                }
                if let Some(st) = &nrtm4_status {
                    tx.record_nrtm4_client_status(&source, st.clone())?;
                }
                Ok(())
            })
            .map_err(PyErr::from)
    })
    .await
}

/// Sources that are mirrors in these settings, in order.
pub fn mirror_sources(settings: &MirrorSettings) -> HashSet<String> {
    settings
        .sources
        .iter()
        .filter(|s| s.is_mirror())
        .map(|s| s.name.clone())
        .collect()
}

/// `Operation` for an NRTMv4 action.
pub(crate) fn op_for(action: &str) -> Option<Operation> {
    match action {
        "add_modify" => Some(Operation::Add),
        "delete" => Some(Operation::Del),
        _ => None,
    }
}
