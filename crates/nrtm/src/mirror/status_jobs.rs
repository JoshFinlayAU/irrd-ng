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
    let name = path.to_string_lossy().into_owned();
    // `open(roa_filename)`: the OSError names the file.
    let bytes = tokio::task::spawn_blocking(move || std::fs::read(path))
        .await
        .map_err(|e| PyErr::Other(e.to_string()))?
        .map_err(|e| PyErr::Os(crate::mirror::pyerr::os_error_text(&e, Some(&name))))?;
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
    let parsed = RoaImport::parse(roa_json, slurm_json, Some(&jobs.pseudo_irr_remarks))?;
    let scopefilter = ScopeFilterValidator::new(settings.scopefilter.clone());
    let mut objects = Vec::with_capacity(parsed.roas.len());
    for roa in &parsed.roas {
        objects.push(roa.pseudo_object(&jobs.pseudo_irr_remarks, &scopefilter)?);
    }
    if let Some(i) = parsed.duplicate_at_commit {
        // v4 has logged the import as done before its commit fails.
        tracing::info!(target: LOG_TARGET, "{}", rmsg::roa_import_imported(&roa_source, &slurm_shown, parsed.roas.len()));
        return Err(importer::duplicate_error(&parsed.roas[i]));
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

// ---------------------------------------------------------------------
// Dry runs: what a job would change, without writing. irrd-ng only; the
// full-scale parity check compares these with v4's validators run
// read-only on the same data.
// ---------------------------------------------------------------------

fn sha256_hex(text: &str) -> String {
    use sha2::Digest;
    crate::mirror::retrieval::hex(&sha2::Sha256::digest(text.as_bytes()))
}

fn op_label(before: bool, now: bool, adding: bool) -> &'static str {
    match (adding, before, now) {
        (true, false, true) => "add",
        (false, true, false) => "delete",
        _ => "-",
    }
}

/// The ROA import's pseudo-IRR objects and route status changes, one line
/// each: `pseudo, class, key, sha256(text), scope filter status, ip_first,
/// ip_last, prefix` and `rpki, pk, new status, journal operation`.
pub fn dry_run_roa_import(
    store: &Store,
    settings: &MirrorSettings,
    roa_json: &str,
    slurm_json: Option<&str>,
) -> Result<Vec<String>, RoaImportError> {
    let jobs = &settings.status_jobs;
    let parsed = RoaImport::parse(roa_json, slurm_json, Some(&jobs.pseudo_irr_remarks))?;
    let scopefilter = ScopeFilterValidator::new(settings.scopefilter.clone());
    let mut out = Vec::new();
    for roa in &parsed.roas {
        let obj = roa.pseudo_object(&jobs.pseudo_irr_remarks, &scopefilter)?;
        out.push(format!(
            "pseudo\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            obj.object_class,
            obj.rpsl_pk,
            sha256_hex(&obj.object_text),
            obj.scopefilter_status.pg_label(),
            roa.prefix.net(),
            roa.prefix.broadcast(),
            roa.prefix_str,
        ));
    }
    if let Some(i) = parsed.duplicate_at_commit {
        return Err(importer::duplicate_error(&parsed.roas[i]));
    }
    let validator =
        BulkRouteRoaValidator::from_roas(&parsed.roas, settings.rpki_excluded_sources.clone());
    let r = store
        .read()
        .map_err(|e| RoaImportError::Other(e.to_string()))?;
    let (valid, invalid, not_found) = validator
        .validate_all_routes(&r.view())
        .map_err(|e| RoaImportError::Other(e.to_string()))?;
    for (list, adding) in [(&valid, true), (&not_found, true), (&invalid, false)] {
        for c in list.iter() {
            let before = store::object_is_visible(
                c.old_status,
                c.scopefilter_status,
                c.route_preference_status,
            );
            let now = store::object_is_visible(
                c.rpki_status,
                c.scopefilter_status,
                c.route_preference_status,
            );
            out.push(format!(
                "rpki\t{}\t{}\t{}",
                c.pk,
                c.rpki_status.pg_label(),
                op_label(before, now, adding)
            ));
        }
    }
    Ok(out)
}

/// The scope filter update's changes: `scopefilter, pk, new status,
/// journal operation`.
pub fn dry_run_scopefilter(store: &Store, settings: &MirrorSettings) -> store::Result<Vec<String>> {
    let validator = ScopeFilterValidator::new(settings.scopefilter.clone());
    let r = store.read()?;
    let (in_scope, out_as, out_prefix) = validator.validate_all_rpsl_objects(&r.view())?;
    let mut out = Vec::new();
    for (list, adding) in [(&in_scope, true), (&out_as, false), (&out_prefix, false)] {
        for c in list.iter() {
            let before =
                store::object_is_visible(c.rpki_status, c.old_status, c.route_preference_status);
            let now = store::object_is_visible(
                c.rpki_status,
                c.scopefilter_status,
                c.route_preference_status,
            );
            out.push(format!(
                "scopefilter\t{}\t{}\t{}",
                c.pk,
                c.scopefilter_status.pg_label(),
                op_label(before, now, adding)
            ));
        }
    }
    Ok(out)
}

/// The full route preference update's changes: `routepref, pk, new
/// status, journal operation`.
pub fn dry_run_route_preference(store: &Store) -> store::Result<Vec<String>> {
    let settings = store.settings();
    if !settings.route_preference_enabled() {
        return Ok(Vec::new());
    }
    let r = store.read()?;
    let changes = rpki::routepref::route_preference_changes(
        &r.view(),
        rpki::routepref::source_preferences(&settings),
        None,
    )?;
    let mut out = Vec::new();
    for (list, status, op) in [
        (&changes.visible, "visible", "add"),
        (&changes.suppressed, "suppressed", "delete"),
    ] {
        for c in list.iter() {
            let shown = store::object_is_visible(
                c.rpki_status,
                c.scopefilter_status,
                store::RoutePreferenceStatus::Visible,
            );
            out.push(format!(
                "routepref\t{}\t{status}\t{}",
                c.pk,
                if shown { op } else { "-" }
            ));
        }
    }
    Ok(out)
}

/// Fetch the ROA (and SLURM) files as the import does.
pub async fn fetch_roa_files(settings: &MirrorSettings) -> Result<(String, Option<String>), PyErr> {
    let roa_source = settings
        .status_jobs
        .roa_source
        .clone()
        .ok_or_else(|| PyErr::Other("rpki.roa_source is not set".to_owned()))?;
    fetch(settings, &roa_source).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use store::{
        DatabaseOperation, IpPrefix, Json, NewRpslObject, RoutePreferenceStatus, RpkiStatus,
        ScopeFilterStatus, SourceSettings, StoreOptions, StoreSettings,
    };

    fn open(dir: &tempfile::TempDir, settings: StoreSettings) -> Store {
        let mut o = StoreOptions::new(dir.path());
        o.initial_map_size = 64 << 20;
        let s = Store::open(&o, settings).expect("store");
        s.set_route_preference_hook(Some(rpki::route_preference_hook));
        s
    }

    fn route(source: &str, prefix: &str, asn: u32) -> NewRpslObject {
        let p = IpPrefix::parse(prefix).expect("prefix");
        let last = p.last();
        let ip_last = match p.addr {
            std::net::IpAddr::V4(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(last as u32)),
            std::net::IpAddr::V6(_) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(last)),
        };
        let class = if p.version() == 4 { "route" } else { "route6" };
        NewRpslObject {
            rpsl_pk: format!("{prefix}AS{asn}"),
            source: source.to_owned(),
            object_class: class.to_owned(),
            parsed_data: Json::canonical(&format!(
                r#"{{"source": "{source}", "origin": "AS{asn}"}}"#
            ))
            .expect("json"),
            object_text: format!("{class}: {prefix}\norigin: AS{asn}\nsource: {source}\n"),
            ip_first: Some(p.addr),
            ip_last: Some(ip_last),
            prefix: Some(p),
            prefix_length: Some(u32::from(p.len)),
            asn_first: Some(asn),
            asn_last: Some(asn),
            rpki_status: RpkiStatus::NotFound,
            scopefilter_status: ScopeFilterStatus::InScope,
            route_preference_status: RoutePreferenceStatus::Visible,
        }
    }

    fn settings(prefs: &[(&str, i64)]) -> StoreSettings {
        let mut sources = HashMap::new();
        for name in ["AUTH", "LOW"] {
            sources.insert(
                name.to_owned(),
                SourceSettings {
                    keep_journal: true,
                    route_object_preference: prefs
                        .iter()
                        .find(|(n, _)| *n == name)
                        .map(|(_, p)| *p),
                    ..Default::default()
                },
            );
        }
        StoreSettings {
            sources,
            rpki_enabled: true,
            ..Default::default()
        }
    }

    fn mirror_settings() -> MirrorSettings {
        MirrorSettings {
            rpki_enabled: true,
            status_jobs: StatusJobSettings {
                roa_source: Some("file:///unused".into()),
                pseudo_irr_remarks: "ROA for AS{asn}\n".into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn statuses(store: &Store, source: &str) -> Vec<(String, RpkiStatus, RoutePreferenceStatus)> {
        let r = store.read().expect("read");
        let v = r.view();
        let mut out = Vec::new();
        for class in ["route", "route6"] {
            for item in v.objects(Some(source), Some(class)).expect("objects") {
                let (_, o) = item.expect("object");
                out.push((
                    o.rpsl_pk.to_owned(),
                    o.rpki_status,
                    o.route_preference_status,
                ));
            }
        }
        out
    }

    fn journal(
        store: &Store,
        source: &str,
    ) -> Vec<(i64, DatabaseOperation, JournalEntryOrigin, String)> {
        let r = store.read().expect("read");
        let v = r.view();
        v.journal(Some(source), None, None)
            .expect("journal")
            .map(|e| {
                let e = e.expect("entry");
                (e.serial_nrtm, e.operation, e.origin, e.rpsl_pk.to_owned())
            })
            .collect()
    }

    // ROAImportRunner end to end: pseudo-IRR objects, the two
    // transactions, and journal entries only for visibility changes.
    #[test]
    fn roa_import_revalidates_and_journals() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open(&dir, settings(&[]));
        store
            .write(|tx| {
                for (p, a) in [
                    ("192.0.2.0/24", 65001),
                    ("198.51.100.0/24", 65002),
                    ("2001:db8::/32", 65003),
                ] {
                    tx.upsert_rpsl_object(
                        &route("AUTH", p, a),
                        JournalEntryOrigin::AuthChange,
                        None,
                        None,
                    )?;
                }
                Ok(())
            })
            .expect("seed");
        let base = journal(&store, "AUTH").len();
        let ms = mirror_settings();
        let roas = r#"{"roas": [
            {"asn": "AS65001", "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "t"},
            {"asn": "AS65099", "prefix": "198.51.100.0/23", "maxLength": 24, "ta": "t"}
        ]}"#;
        import_and_validate(&store, &ms, roas, None).expect("import");
        assert_eq!(
            statuses(&store, "AUTH"),
            vec![
                (
                    "192.0.2.0/24AS65001".to_owned(),
                    RpkiStatus::Valid,
                    RoutePreferenceStatus::Visible
                ),
                (
                    "198.51.100.0/24AS65002".to_owned(),
                    RpkiStatus::Invalid,
                    RoutePreferenceStatus::Visible
                ),
                (
                    "2001:db8::/32AS65003".to_owned(),
                    RpkiStatus::NotFound,
                    RoutePreferenceStatus::Visible
                ),
            ]
        );
        // Valid stays visible: no entry. Invalid: a deletion.
        let j = journal(&store, "AUTH");
        assert_eq!(
            j[base..]
                .iter()
                .map(|e| (e.1, e.2, e.3.clone()))
                .collect::<Vec<_>>(),
            vec![(
                DatabaseOperation::Delete,
                JournalEntryOrigin::RpkiStatus,
                "198.51.100.0/24AS65002".to_owned()
            )]
        );
        let rpki = statuses(&store, "RPKI");
        assert_eq!(rpki.len(), 2);
        assert!(rpki.iter().all(|(_, s, _)| *s == RpkiStatus::Valid));
        assert!(journal(&store, "RPKI").is_empty());

        // The ROA goes away: invalid becomes not_found, journalled as an
        // addition; the old pseudo-IRR objects are replaced.
        let roas2 = r#"{"roas": [{"asn": "AS65001", "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "t"}]}"#;
        import_and_validate(&store, &ms, roas2, None).expect("import");
        assert_eq!(statuses(&store, "RPKI").len(), 1);
        let j = journal(&store, "AUTH");
        assert_eq!(
            j.last().map(|e| (e.1, e.2)),
            Some((
                DatabaseOperation::AddOrUpdate,
                JournalEntryOrigin::RpkiStatus
            ))
        );
        let r = store.read().expect("read");
        assert_eq!(r.view().roas().expect("roas").len(), 1);
    }

    #[tokio::test]
    async fn missing_roa_file_is_an_os_error_naming_it() {
        let mut ms = mirror_settings();
        ms.status_jobs.roa_source = Some("file:///nonexistent/roas.json".into());
        let e = fetch_roa_files(&ms).await.expect_err("missing");
        assert_eq!(
            e,
            PyErr::Os("[Errno 2] No such file or directory: '/nonexistent/roas.json'".into())
        );
    }

    // The v4 quirk: a ROA repeated under another trust anchor fails the
    // whole import and the previous ROAs stay.
    #[test]
    fn duplicate_roa_keeps_previous_state() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open(&dir, settings(&[]));
        let ms = mirror_settings();
        let ok = r#"{"roas": [{"asn": "AS65001", "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "a"}]}"#;
        import_and_validate(&store, &ms, ok, None).expect("import");
        let dup = r#"{"roas": [
            {"asn": "AS65002", "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "a"},
            {"asn": "AS65002", "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "b"}
        ]}"#;
        let e = import_and_validate(&store, &ms, dup, None).expect_err("duplicate");
        assert!(
            e.to_string()
                .contains("rpsl_objects_rpsl_pk_source_class_unique")
        );
        assert_eq!(statuses(&store, "RPKI")[0].0, "192.0.2.0/24AS65001/ML24");
    }

    // Route preference: the full runner, and the pre-commit hook for
    // changed prefixes only, with journal entries for visible objects.
    #[test]
    fn route_preference_runner_and_hook() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open(&dir, settings(&[("AUTH", 900), ("LOW", 100)]));
        // Written before the hook can see AUTH: both visible at first.
        store
            .write(|tx| {
                tx.upsert_rpsl_object(
                    &route("LOW", "192.0.2.0/25", 65009),
                    JournalEntryOrigin::Mirror,
                    None,
                    None,
                )?;
                tx.upsert_rpsl_object(
                    &route("LOW", "203.0.113.0/24", 65009),
                    JournalEntryOrigin::Mirror,
                    None,
                    None,
                )
            })
            .expect("low");
        assert!(
            statuses(&store, "LOW")
                .iter()
                .all(|s| s.2 == RoutePreferenceStatus::Visible)
        );
        // The hook runs for 192.0.2.0/24 when AUTH's route arrives.
        store
            .write(|tx| {
                tx.upsert_rpsl_object(
                    &route("AUTH", "192.0.2.0/24", 65001),
                    JournalEntryOrigin::AuthChange,
                    None,
                    None,
                )
            })
            .expect("auth");
        let low = statuses(&store, "LOW");
        assert_eq!(low[0].2, RoutePreferenceStatus::Suppressed);
        assert_eq!(low[1].2, RoutePreferenceStatus::Visible);
        let j = journal(&store, "LOW");
        assert_eq!(
            j.last().map(|e| (e.1, e.2, e.3.clone())),
            Some((
                DatabaseOperation::Delete,
                JournalEntryOrigin::RoutePreference,
                "192.0.2.0/25AS65009".to_owned()
            ))
        );
        // Swap the preferences and run the full update.
        store.set_settings(settings(&[("AUTH", 100), ("LOW", 900)]));
        run_route_preference_update(&store);
        assert_eq!(statuses(&store, "LOW")[0].2, RoutePreferenceStatus::Visible);
        assert_eq!(
            statuses(&store, "AUTH")[0].2,
            RoutePreferenceStatus::Suppressed
        );
        // Preferences gone: everything visible again.
        store.set_settings(settings(&[("LOW", 0)]));
        run_route_preference_update(&store);
        assert_eq!(
            statuses(&store, "AUTH")[0].2,
            RoutePreferenceStatus::Suppressed
        );
        store.set_settings(settings(&[("LOW", 5)]));
        run_route_preference_update(&store);
        assert_eq!(
            statuses(&store, "AUTH")[0].2,
            RoutePreferenceStatus::Visible
        );
    }

    // The dry runs report what the jobs would change and write nothing.
    #[test]
    fn dry_runs_write_nothing() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open(&dir, settings(&[("AUTH", 900), ("LOW", 100)]));
        store
            .write(|tx| {
                tx.upsert_rpsl_object(
                    &route("AUTH", "192.0.2.0/24", 65001),
                    JournalEntryOrigin::AuthChange,
                    None,
                    None,
                )?;
                tx.upsert_rpsl_object(
                    &route("AUTH", "10.0.0.0/8", 64500),
                    JournalEntryOrigin::AuthChange,
                    None,
                    None,
                )
            })
            .expect("seed");
        store
            .write(|tx| {
                tx.upsert_rpsl_object(
                    &route("LOW", "192.0.2.0/25", 65009),
                    JournalEntryOrigin::Mirror,
                    None,
                    None,
                )
            })
            .expect("low");
        let before = journal(&store, "AUTH").len() + journal(&store, "LOW").len();
        let mut ms = mirror_settings();
        let lines = dry_run_roa_import(
            &store,
            &ms,
            r#"{"roas": [{"asn": "AS65099", "prefix": "192.0.2.0/24", "maxLength": 25, "ta": "t"}]}"#,
            None,
        )
        .expect("dry run");
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("pseudo\troute\t192.0.2.0/24AS65099/ML25\t"));
        assert!(lines[0].ends_with("\tin_scope\t192.0.2.0\t192.0.2.255\t192.0.2.0/24"));
        // The LOW /25 is already suppressed by route preference: no entry.
        assert!(lines.iter().any(|l| l.ends_with("\tinvalid\tdelete")));
        assert!(lines.iter().any(|l| l.ends_with("\tinvalid\t-")));
        ms.scopefilter = rpki::ScopeFilterConfig {
            asns: [64500].into_iter().collect(),
            ..Default::default()
        };
        let sf = dry_run_scopefilter(&store, &ms).expect("dry run");
        assert_eq!(sf.len(), 1);
        assert!(sf[0].ends_with("\tout_scope_as\tdelete"));
        store.set_settings(settings(&[("AUTH", 100), ("LOW", 900)]));
        let rp = dry_run_route_preference(&store).expect("dry run");
        assert_eq!(rp.len(), 2);
        assert!(statuses(&store, "RPKI").is_empty());
        assert_eq!(statuses(&store, "AUTH")[0].1, RpkiStatus::NotFound);
        assert_eq!(
            journal(&store, "AUTH").len() + journal(&store, "LOW").len(),
            before
        );
    }

    #[test]
    fn scopefilter_update_journals_visibility_changes() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open(&dir, settings(&[]));
        store
            .write(|tx| {
                tx.upsert_rpsl_object(
                    &route("AUTH", "10.1.0.0/16", 65001),
                    JournalEntryOrigin::AuthChange,
                    None,
                    None,
                )?;
                tx.upsert_rpsl_object(
                    &route("AUTH", "192.0.2.0/24", 64500),
                    JournalEntryOrigin::AuthChange,
                    None,
                    None,
                )
            })
            .expect("seed");
        let mut ms = mirror_settings();
        ms.scopefilter = rpki::ScopeFilterConfig {
            prefixes: vec![IpPrefix::parse("10.0.0.0/8").expect("p")],
            asns: [64500].into_iter().collect(),
            ..Default::default()
        };
        run_scopefilter_update(&store, &ms);
        let r = store.read().expect("read");
        let v = r.view();
        let got: Vec<ScopeFilterStatus> = v
            .objects(Some("AUTH"), Some("route"))
            .expect("objects")
            .map(|i| i.expect("o").1.scopefilter_status)
            .collect();
        assert_eq!(
            got,
            vec![
                ScopeFilterStatus::OutScopePrefix,
                ScopeFilterStatus::OutScopeAs
            ]
        );
        drop(r);
        let j = journal(&store, "AUTH");
        assert_eq!(j.len(), 4);
        assert!(j[2..].iter().all(|e| e.1 == DatabaseOperation::Delete && e.2 == JournalEntryOrigin::ScopeFilter));
    }
}
