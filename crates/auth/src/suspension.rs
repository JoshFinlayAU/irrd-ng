//! `irrd/updates/suspension.py`: suspend and reactivate a mntner with the
//! objects it maintains.

use std::collections::{HashMap, HashSet};

use rpsl::RpslObject;
use store::{JournalEntryOrigin, Uuid, WriteTx};

use crate::settings::SubmitSettings;
use crate::store_util::{self, Row, source_of};
use crate::{Internal, messages};

/// v4's logger.
const LOG_TARGET: &str = "irrd.updates.suspension";

/// Why a suspension or reactivation did not happen: v4's `ValueError`
/// (reported to the submitter) or anything else.
#[derive(Debug)]
pub(crate) enum SuspensionError {
    Value(String),
    Internal(Internal),
}

impl From<Internal> for SuspensionError {
    fn from(e: Internal) -> Self {
        SuspensionError::Internal(e)
    }
}

impl From<store::StoreError> for SuspensionError {
    fn from(e: store::StoreError) -> Self {
        match e {
            store::StoreError::ValueError(m) => SuspensionError::Value(m),
            other => SuspensionError::Internal(Internal::from(other)),
        }
    }
}

/// `suspend_for_mntner(database_handler, suspended_mntner)`: the rows that
/// were suspended.
pub(crate) fn suspend_for_mntner(
    tx: &mut WriteTx<'_, '_>,
    settings: &SubmitSettings,
    mntner: &RpslObject,
) -> Result<Vec<Row>, SuspensionError> {
    let pk = mntner.pk();
    let source = source_of(mntner)?;
    let prelude = format!("suspension {pk}");
    if !settings.source(&source).authoritative {
        return Err(SuspensionError::Value(
            messages::suspension_not_authoritative(&source),
        ));
    }
    tracing::info!(target: LOG_TARGET, "{prelude}: Starting suspension for {mntner}");

    let query1 = store_util::lookup_attrs_in(tx, &source, &["mnt-by"], &pk)?;
    let query2 = store_util::objects_by_pks(tx, &source, "mntner", &[&pk])?;
    if query2.is_empty() {
        let msg = messages::suspend_mntner_missing(&pk, &source);
        tracing::info!(target: LOG_TARGET, "{prelude}: error: {msg}");
        return Err(SuspensionError::Value(msg));
    }

    let mut active_cache: HashMap<String, bool> = HashMap::new();
    let mut suspended: Vec<Row> = Vec::new();
    for row in query1.into_iter().chain(query2) {
        if suspended.contains(&row) {
            continue;
        }
        let mut seen = HashSet::new();
        let mut mntners_active = Vec::new();
        for m in row.list("mnt-by") {
            if !seen.insert(m.clone()) || m == pk {
                continue;
            }
            let active = match active_cache.get(&m) {
                Some(a) => *a,
                None => {
                    let a = !store_util::objects_by_pks(tx, &source, "mntner", &[&m])?.is_empty();
                    active_cache.insert(m.clone(), a);
                    a
                }
            };
            if active {
                mntners_active.push(m);
            }
        }
        if row.rpsl_pk != pk && !mntners_active.is_empty() {
            tracing::info!(
                target: LOG_TARGET,
                "{prelude}: Skipping suspension of {}/{} because of remaining active mntners {:?}",
                row.object_class,
                row.rpsl_pk,
                mntners_active
            );
            continue;
        }
        tracing::info!(target: LOG_TARGET, "{prelude}: Suspending {}/{}", row.object_class, row.rpsl_pk);
        tx.suspend_rpsl_object(row.pk)?;
        suspended.push(row);
    }
    Ok(suspended)
}

/// `reactivate_for_mntner(database_handler, reactivated_mntner)`: the
/// restored objects (as `class/pk/source`) and the info messages.
pub(crate) fn reactivate_for_mntner(
    tx: &mut WriteTx<'_, '_>,
    settings: &SubmitSettings,
    mntner: &RpslObject,
) -> Result<(Vec<String>, Vec<String>), SuspensionError> {
    let pk = mntner.pk();
    let source = source_of(mntner)?;
    let prelude = format!("reactivation {pk}");
    if !settings.source(&source).authoritative {
        return Err(SuspensionError::Value(
            messages::suspension_not_authoritative(&source),
        ));
    }
    tracing::info!(target: LOG_TARGET, "{prelude}: Starting reactivation for for {mntner}");

    if !store_util::objects_by_pks(tx, &source, "mntner", &[&pk])?.is_empty() {
        let msg = messages::reactivate_active_exists(&source, &pk);
        tracing::info!(target: LOG_TARGET, "{prelude}: error: {msg}");
        return Err(SuspensionError::Value(msg));
    }

    let mut all = tx.read()?.suspended_objects()?;
    // RPSLDatabaseSuspendedQuery orders by timestamp; within one timestamp
    // irrd-ng's row UUIDs follow insertion order.
    all.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then(a.pk.cmp(&b.pk)));
    let mut results: Vec<store::SuspendedObjectRow> = all
        .iter()
        .filter(|r| r.source == source && r.rpsl_pk == pk && r.object_class == "mntner")
        .cloned()
        .collect();
    if results.is_empty() {
        let msg = messages::reactivate_not_suspended(&pk, &source);
        tracing::info!(target: LOG_TARGET, "{prelude}: error: {msg}");
        return Err(SuspensionError::Value(msg));
    }
    results.extend(
        all.iter()
            .filter(|r| r.source == source && r.mntners.iter().any(|m| *m == pk))
            .cloned(),
    );

    let scopefilter = rpki::ScopeFilterValidator::new(settings.scopefilter.clone());
    let mut restored_pks: Vec<Uuid> = Vec::new();
    let mut restored: Vec<String> = Vec::new();
    let mut infos: Vec<String> = Vec::new();
    for result in results {
        if restored_pks.contains(&result.pk) {
            continue;
        }
        let obj = store_util::parse_stored(&result.object_text, settings)?;
        let obj_source = source_of(&obj)?;
        if !store_util::objects_by_pks(tx, &source, obj.rpsl_object_class(), &[&obj.pk()])?
            .is_empty()
        {
            let msg = messages::reactivate_skipped(&obj.to_string());
            tracing::info!(target: LOG_TARGET, "{prelude}: {msg}");
            infos.push(msg);
            continue;
        }
        let prefix = obj.prefix.as_ref().and_then(store_util::store_prefix);
        let scope = scopefilter.validate_rpsl_object(
            &obj_source,
            obj.rpsl_object_class(),
            prefix.as_ref(),
            obj.asn_first,
        );
        let mut rpki_status = store::RpkiStatus::NotFound;
        if settings.rpki_enabled
            && obj.is_route()
            && let (Some(asn), Some(route)) = (obj.asn_first.filter(|a| *a != 0), prefix)
        {
            let view = tx.read()?;
            rpki_status = rpki::validate_route_single(
                &view,
                &route,
                asn,
                settings.source(&source).rpki_excluded,
            )
            .map_err(Internal::from)?;
        }
        let row = crate::new_object(&obj, &settings.rpsl, Some(rpki_status), Some(scope))?;
        tx.upsert_rpsl_object(
            &row,
            JournalEntryOrigin::Suspension,
            None,
            Some(result.original_created),
        )?;
        restored_pks.push(result.pk);
        tracing::info!(target: LOG_TARGET, "{prelude}: Restoring object {obj}");
        restored.push(obj.to_string());
    }
    tx.delete_suspended_rpsl_objects(&restored_pks)?;
    Ok((restored, infos))
}
