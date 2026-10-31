//! The status jobs v4's scheduler runs besides mirroring
//! (`irrd/mirroring/mirror_runners_import.py`): `ROAImportRunner`,
//! `ScopeFilterUpdateRunner` and `RoutePreferenceUpdateRunner`.
//!
//! Each keeps v4's transactions. The ROA import commits the new ROAs and
//! RPKI pseudo-IRR objects first, then re-validates every route in a second
//! transaction and only then sends the notification mails. Failures are
//! logged and the job ends, as v4's runner process does.

use std::sync::Arc;

use rpki::importer::{self, RoaImport, RoaImportError};
use rpki::notifications::{self, NotifySettings};
use rpki::{BulkRouteRoaValidator, ScopeFilterValidator, messages as rmsg};
use store::{JournalEntryOrigin, Store};

use crate::mirror::pyerr::PyErr;
use crate::mirror::retrieval::Retriever;
use crate::mirror::runner::LOG_TARGET;
use crate::mirror::settings::MirrorSettings;

/// v4's process name for the ROA import.
pub const ROA_IMPORT_RUNNER: &str = "ROAImportRunner";
/// v4's process name for the scope filter update.
pub const SCOPEFILTER_RUNNER: &str = "ScopeFilterUpdateRunner";
/// v4's process name for the route preference update.
pub const ROUTEPREF_RUNNER: &str = "RoutePreferenceUpdateRunner";

/// What `get_setting("scopefilter...")` returned when the scheduler last
/// looked, for `_check_scopefilter_change()`: the prefixes and ASNs as
/// written (Python `repr()` of each item, so `1` and `'1'` differ as they
/// do in v4) and the names of the excluded sources.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeFilterFingerprint {
    /// `list(get_setting("scopefilter.prefixes", []))`
    pub prefixes: Vec<String>,
    /// `list(get_setting("scopefilter.asns", []))`
    pub asns: Vec<String>,
    /// Sources whose settings dict has a truthy `scopefilter_excluded`.
    pub excluded: std::collections::BTreeSet<String>,
}

/// Settings for the status jobs.
#[derive(Debug, Clone, Default)]
pub struct StatusJobSettings {
    /// `rpki.roa_source`, when set (truthy).
    pub roa_source: Option<String>,
    /// `rpki.slurm_source`, when set (truthy).
    pub slurm_source: Option<String>,
    /// `int(rpki.roa_import_timer)`
    pub roa_import_timer: i64,
    /// `rpki.pseudo_irr_remarks`
    pub pseudo_irr_remarks: String,
    /// The `rpki.notify_invalid_*` settings.
    pub notify: NotifySettings,
    /// The `email.*` settings.
    pub mail: mail::MailSettings,
    /// Some source sets a (truthy) `route_object_preference`.
    pub route_preference_enabled: bool,
    /// `int(route_object_preference.update_timer)`
    pub route_preference_update_timer: i64,
    /// `get_setting("scopefilter")` is truthy, with what it holds.
    pub scopefilter: Option<ScopeFilterFingerprint>,
}

async fn blocking_io<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    tokio::task::spawn_blocking(f).await.ok()
}

/// `ROAImportRunner().run()`.
pub async fn run_roa_import(store: Store, settings: Arc<MirrorSettings>) {
    let jobs = &settings.status_jobs;
    let Some(roa_source) = jobs.roa_source.clone() else {
        return;
    };
    let slurm_shown = jobs.slurm_source.clone().unwrap_or_else(|| "None".into());
    tracing::info!(target: LOG_TARGET, "{}", rmsg::roa_import_running(&roa_source, &slurm_shown));

    // _import_roas(): the files first (v4 deletes the old data first, in
    // the same uncommitted transaction, so the order is not visible).
    let fetched = fetch(&settings, &roa_source).await;
    let (roa_text, slurm_text) = match fetched {
        Ok(t) => t,
        Err(PyErr::Os(m)) => {
            tracing::error!(target: LOG_TARGET, "{}", rmsg::roa_import_os_error(&m));
            return;
        }
        Err(e) => {
            tracing::error!(target: LOG_TARGET, "{}", rmsg::roa_import_exception(e.message()));
            return;
        }
    };
    let settings2 = settings.clone();
    let outcome = blocking_io(move || {
        import_and_validate(&store, &settings2, &roa_text, slurm_text.as_deref())
    })
    .await;
    match outcome {
        Some(Ok(())) | None => {}
        Some(Err(RoaImportError::Parser(m))) | Some(Err(RoaImportError::Other(m))) => {
            tracing::error!(target: LOG_TARGET, "{}", rmsg::roa_import_exception(&m));
        }
    }
}

async fn fetch(
    settings: &MirrorSettings,
    roa_source: &str,
) -> Result<(String, Option<String>), PyErr> {
    let retriever = Retriever::new(settings.download_timeout)?;
    let slurm = match &settings.status_jobs.slurm_source {
        Some(s) => Some(retriever.contents(s).await?),
        None => None,
    };
    let file = retriever.file(roa_source, None).await?;
    let path = file.path().to_path_buf();
    let bytes = tokio::task::spawn_blocking(move || std::fs::read(path))
        .await
        .map_err(|e| PyErr::Other(e.to_string()))?
        .map_err(|e| PyErr::Os(crate::mirror::pyerr::os_error_text(&e, None)))?;
    drop(file);
    let text = String::from_utf8(bytes).map_err(|e| PyErr::Value(e.to_string()))?;
    Ok((text, slurm))
}

/// The blocking part of the ROA import: both transactions and the mails.
pub fn import_and_validate(
    store: &Store,
    settings: &MirrorSettings,
    roa_json: &str,
    slurm_json: Option<&str>,
) -> Result<(), RoaImportError> {
    let jobs = &settings.status_jobs;
    let roa_source = jobs.roa_source.clone().unwrap_or_default();
    let slurm_shown = jobs.slurm_source.clone().unwrap_or_else(|| "None".into());
    let parsed = RoaImport::parse(roa_json, slurm_json)?;
    let scopefilter = ScopeFilterValidator::new(settings.scopefilter.clone());
    let mut objects = Vec::with_capacity(parsed.roas.len());
    for roa in &parsed.roas {
        objects.push(roa.pseudo_object(&jobs.pseudo_irr_remarks, &scopefilter)?);
    }
    if let Some(dup) = parsed.first_duplicate() {
        return Err(importer::duplicate_error(dup));
    }

    // First transaction, journaling disabled: replace every ROA and every
    // pseudo-IRR object.
    let roas = Arc::new(parsed.roas);
    let objects = Arc::new(objects);
    let (r2, o2) = (roas.clone(), objects.clone());
    let reserve = objects.len().saturating_mul(2048);
    store
        .write_reserving(reserve, move |tx| {
            tx.disable_journaling();
            tx.delete_all_roa_objects()?;
            tx.delete_all_rpsl_objects_with_journal(importer::RPKI_IRR_PSEUDO_SOURCE, true)?;
            for (roa, obj) in r2.iter().zip(o2.iter()) {
                if let Some(prefix) = roa.ip_prefix() {
                    tx.insert_roa_object(
                        roa.prefix.version(),
                        prefix,
                        i64::from(roa.asn),
                        roa.max_length,
                        &roa.trust_anchor,
                    )?;
                }
                tx.upsert_rpsl_object(obj, JournalEntryOrigin::PseudoIrr, None, None)?;
            }
            Ok(())
        })
        .map_err(|e| RoaImportError::Other(e.to_string()))?;
    tracing::info!(target: LOG_TARGET, "{}", rmsg::roa_import_imported(&roa_source, &slurm_shown, roas.len()));

    // Second transaction: re-validate every route.
    let validator = BulkRouteRoaValidator::from_roas(&roas, settings.rpki_excluded_sources.clone());
    let validator = Arc::new(validator);
    let (valid, invalid, not_found) = store
        .write(move |tx| {
            let changes = {
                let view = tx.read()?;
                validator.validate_all_routes(&view)?
            };
            tx.update_rpki_status(&changes.0, &changes.1, &changes.2)?;
            Ok(changes)
        })
        .map_err(|e| RoaImportError::Other(e.to_string()))?;

    let notified = {
        let mails = match store.read() {
            Ok(r) => notifications::invalid_owner_notifications(
                &r.view(),
                &jobs.notify,
                &settings.rpsl,
                &invalid,
            )
            .map_err(|e| RoaImportError::Other(e.to_string()))?,
            Err(e) => return Err(RoaImportError::Other(e.to_string())),
        };
        notifications::send_notifications(&jobs.mail, &mails)
    };
    tracing::info!(
        target: LOG_TARGET,
        "{}",
        rmsg::rpki_status_updated(valid.len(), invalid.len(), not_found.len(), notified)
    );
    Ok(())
}

/// `ScopeFilterUpdateRunner().run()`.
pub fn run_scopefilter_update(store: &Store, settings: &MirrorSettings) {
    let validator = Arc::new(ScopeFilterValidator::new(settings.scopefilter.clone()));
    let r = store.write(move |tx| {
        let changes = {
            let view = tx.read()?;
            validator.validate_all_rpsl_objects(&view)?
        };
        tx.update_scopefilter_status(&changes.0, &changes.1, &changes.2)?;
        Ok((changes.0.len(), changes.1.len(), changes.2.len()))
    });
    match r {
        Ok((a, b, c)) => {
            tracing::info!(target: LOG_TARGET, "{}", rmsg::scopefilter_updated(a, b, c))
        }
        Err(e) => {
            tracing::error!(target: LOG_TARGET, "{}", rmsg::scopefilter_exception(&e.to_string()))
        }
    }
}

/// `RoutePreferenceUpdateRunner().run()`.
pub fn run_route_preference_update(store: &Store) {
    let r = store.write(|tx| rpki::routepref::update_route_preference_status(tx, None));
    match r {
        Ok(()) => tracing::info!(target: LOG_TARGET, "{}", rmsg::ROUTEPREF_COMMIT_COMPLETE),
        Err(e) => {
            tracing::error!(target: LOG_TARGET, "{}", rmsg::routepref_exception(&e.to_string()))
        }
    }
}
