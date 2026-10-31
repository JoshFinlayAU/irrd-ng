//! The write transaction: v4's `DatabaseHandler` and
//! `DatabaseStatusTracker` semantics on top of one LMDB write transaction,
//! plus the raw row API the v4 importer uses.
//!
//! One [`WriteTx`] is one v4 database transaction: everything done through
//! it commits together when the closure passed to
//! [`crate::Store::write`] returns `Ok`, after v4's `finalise_transaction`
//! has updated `database_status`, or is discarded when it returns `Err`.
//!
//! v4 buffers upserts and writes their journal entries when the buffer is
//! flushed (before deletes, queries and commit, on a duplicate key in the
//! buffer, and every 15,000 objects). The order of journal entries and the
//! serials they get depend on those flush points, so the buffer is kept
//! here too: the objects are written straight away (reads in the same
//! transaction see them, as v4's flush-before-query guarantees), and only
//! the journal records wait for the flush.

use std::collections::{BTreeSet, HashMap, HashSet};

use heed::RwTxn;

use crate::env::{META_NEXT_OBJECT_ID, META_SERIAL_GLOBAL_LAST, Tables};
use crate::error::{Result, StoreError};
use crate::index::{self, object_key, source_prefix};
use crate::keys::{id_bytes, push_str, serial_bytes};
use crate::messages;
use crate::model::{
    AuthApiTokenRow, AuthMntnerRow, AuthPermissionRow, AuthUserRow, AuthWebAuthnRow, ChangeLogRow,
    DatabaseOperation, DatabaseStatus, IpPrefix, JournalEntry, JournalEntryOrigin, Json,
    NewRpslObject, Nrtm4ClientStatus, Nrtm4ServerStatus, ProtectedNameRow, RoaRow,
    RoutePreferenceStatus, RpkiStatus, RpslObjectRow, ScopeFilterStatus, SettingRow, StatusChange,
    SuspendedObjectRow, Timestamp, Uuid, object_is_visible,
};
use crate::query;
use crate::read::ReadView;
use crate::records::{JournalEntryRef, RoaValue, RpslObjectRef, decode, encode};
use crate::settings::StoreSettings;

/// v4's `MAX_RECORDS_BUFFER_BEFORE_INSERT`.
pub const MAX_RECORDS_BUFFER_BEFORE_INSERT: usize = 15000;

/// v4's `PROTECTED_NAME_OBJECT_CLASSES`.
pub const PROTECTED_NAME_OBJECT_CLASSES: &[&str] = &["person", "role", "mntner"];

/// v4's `RPKI_IRR_PSEUDO_SOURCE`.
pub const RPKI_IRR_PSEUDO_SOURCE: &str = "RPKI";

/// v4's `RPKI_RELEVANT_OBJECT_CLASSES`.
pub const RPKI_RELEVANT_OBJECT_CLASSES: &[&str] = &["route", "route6"];

struct PendingJournal {
    rpsl_pk: String,
    source: String,
    object_class: String,
    object_text: String,
    visible: bool,
    origin: JournalEntryOrigin,
    source_serial: Option<i64>,
}

/// `DatabaseStatusTracker` state for one transaction.
#[derive(Default)]
struct Tracker {
    new_serials_per_source: HashMap<String, BTreeSet<i64>>,
    sources_seen: HashSet<String>,
    sources_rpsl_data_updated: HashSet<String>,
    newest_mirror_serials: HashMap<String, i64>,
    mirroring_error: HashMap<String, String>,
    exported_serials: HashMap<String, i64>,
    nrtm4_client_status: HashMap<String, Nrtm4ClientStatus>,
    nrtm4_server_status: HashMap<String, Nrtm4ServerStatus>,
    is_serial_synchronised: HashMap<String, bool>,
}

/// What changed in a transaction, for the hooks run around commit
/// (`SessionChangedObjectsTracker`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ChangedObjects {
    /// Object classes touched, for preload and event stream signalling.
    pub object_classes: BTreeSet<String>,
    /// Prefixes of route objects whose route preference must be
    /// re-evaluated before commit.
    pub prefixes_for_routepref: BTreeSet<IpPrefix>,
    /// Sources with new journal entries (published on the event stream).
    pub sources_with_new_serials: BTreeSet<String>,
}

/// A hook run just before commit, inside the transaction, with the
/// prefixes whose route preference may have changed. Installed by the
/// route preference module (Phase 5).
pub type RoutePreferenceHook = fn(&mut WriteTx<'_, '_>, &[IpPrefix]) -> Result<()>;

/// One write transaction. See the module documentation.
pub struct WriteTx<'t, 'e> {
    pub(crate) txn: &'t mut RwTxn<'e>,
    pub(crate) t: Tables,
    pub(crate) settings: &'t StoreSettings,
    journaling_enabled: bool,
    tracker: Tracker,
    pending: Vec<PendingJournal>,
    pending_pk_source: HashSet<(String, String)>,
    roa_buffer: Vec<RoaRow>,
    txn_now: Timestamp,
    changed: ChangedObjects,
    routepref_hook: Option<RoutePreferenceHook>,
}

impl std::fmt::Debug for WriteTx<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteTx")
            .field("journaling_enabled", &self.journaling_enabled)
            .finish_non_exhaustive()
    }
}

impl<'t, 'e> WriteTx<'t, 'e> {
    pub(crate) fn new(
        txn: &'t mut RwTxn<'e>,
        t: Tables,
        settings: &'t StoreSettings,
        routepref_hook: Option<RoutePreferenceHook>,
    ) -> Self {
        WriteTx {
            txn,
            t,
            settings,
            journaling_enabled: true,
            tracker: Tracker::default(),
            pending: Vec::new(),
            pending_pk_source: HashSet::new(),
            roa_buffer: Vec::new(),
            txn_now: Timestamp::now(),
            changed: ChangedObjects::default(),
            routepref_hook,
        }
    }

    /// The transaction start time: what PostgreSQL's `now()` returns for
    /// column defaults such as `created`.
    pub fn transaction_time(&self) -> Timestamp {
        self.txn_now
    }

    /// The settings in force for this transaction.
    pub fn settings(&self) -> &StoreSettings {
        self.settings
    }

    /// Read the store as this transaction sees it, after flushing the
    /// upsert buffer (v4's `execute_query(flush_rpsl_buffer=True)`).
    pub fn read(&mut self) -> Result<ReadView<'_>> {
        self.flush_rpsl_object_writing_buffer()?;
        Ok(ReadView::new(self.t, self.txn))
    }

    /// Read without flushing (`flush_rpsl_buffer=False`).
    pub fn read_unflushed(&self) -> ReadView<'_> {
        ReadView::new(self.t, self.txn)
    }

    fn check_write_permitted(&self) -> Result<()> {
        if self.settings.readonly_standby {
            tracing::error!("{}", messages::READONLY_WRITE);
            return Err(StoreError::ReadOnly);
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // DatabaseHandler
    // -----------------------------------------------------------------

    /// `disable_journaling()`
    pub fn disable_journaling(&mut self) {
        self.journaling_enabled = false;
    }

    /// `enable_journaling()`
    pub fn enable_journaling(&mut self) {
        self.journaling_enabled = true;
    }

    /// `upsert_rpsl_object(rpsl_object, origin, source_serial=..., forced_created_value=...)`.
    ///
    /// Inserts the object, or overwrites the one with the same source,
    /// class and primary key (keeping its row UUID). As v4's
    /// `INSERT .. ON CONFLICT DO UPDATE` sets every column but the key
    /// columns and `pk`, `created` becomes the transaction time (or the
    /// forced value) on overwrite too. A journal entry follows at the next
    /// flush, unless the object is suppressed.
    pub fn upsert_rpsl_object(
        &mut self,
        obj: &NewRpslObject,
        origin: JournalEntryOrigin,
        source_serial: Option<i64>,
        forced_created: Option<Timestamp>,
    ) -> Result<()> {
        self.check_write_permitted()?;
        let pk_source = (obj.rpsl_pk.clone(), obj.source.clone());
        if self.pending_pk_source.contains(&pk_source) {
            self.flush_rpsl_object_writing_buffer()?;
        }
        let update_time = Timestamp::now();
        let existing = query::id_by_key(
            &self.t,
            self.txn,
            &obj.source,
            &obj.object_class,
            &obj.rpsl_pk,
        )?;
        let pk = match existing {
            Some(id) => query::object_by_id(&self.t, self.txn, id)?
                .map(|o| o.pk)
                .unwrap_or_else(Uuid::new_v4),
            None => Uuid::new_v4(),
        };
        let row = RpslObjectRow {
            pk,
            rpsl_pk: obj.rpsl_pk.clone(),
            source: obj.source.clone(),
            object_class: obj.object_class.clone(),
            parsed_data: obj.parsed_data.clone(),
            object_text: obj.object_text.clone(),
            ip_version: obj.ip_first.map(|a| if a.is_ipv4() { 4 } else { 6 }),
            ip_first: obj.ip_first,
            ip_last: obj.ip_last,
            prefix_length: obj.prefix_length,
            prefix: obj.prefix,
            asn_first: obj.asn_first,
            asn_last: obj.asn_last,
            rpki_status: obj.rpki_status,
            scopefilter_status: obj.scopefilter_status,
            route_preference_status: obj.route_preference_status,
            created: forced_created.unwrap_or(self.txn_now),
            updated: update_time,
        };
        self.store_row(&RpslObjectRef::from_row(&row))?;

        self.pending.push(PendingJournal {
            rpsl_pk: obj.rpsl_pk.clone(),
            source: obj.source.clone(),
            object_class: obj.object_class.clone(),
            object_text: obj.object_text.clone(),
            visible: row.is_visible(),
            origin,
            source_serial,
        });
        self.pending_pk_source.insert(pk_source);
        self.object_modified(&obj.object_class, &obj.source, obj.prefix, None);

        if self.pending.len() > MAX_RECORDS_BUFFER_BEFORE_INSERT {
            self.flush_rpsl_object_writing_buffer()?;
        }
        Ok(())
    }

    /// `_flush_rpsl_object_writing_buffer()`: write the journal entries of
    /// buffered upserts, in order.
    pub fn flush_rpsl_object_writing_buffer(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.pending);
        self.pending_pk_source.clear();
        for p in pending {
            // Suppressed objects do not get journal entries: mirrors must
            // not see them.
            if !p.visible {
                continue;
            }
            self.record_operation(
                DatabaseOperation::AddOrUpdate,
                &p.rpsl_pk,
                &p.source,
                &p.object_class,
                &p.object_text,
                p.origin,
                p.source_serial,
            )?;
        }
        Ok(())
    }

    /// `delete_rpsl_object(origin, source=, rpsl_pk=, object_class=,
    /// source_serial=, protect_rpsl_name=)`.
    ///
    /// Returns whether an object was deleted. When none matched, v4 logs an
    /// error and carries on; so does this. `protect_rpsl_name` takes effect
    /// for person, role and mntner objects, as v4 does when it is given the
    /// RPSL object.
    pub fn delete_rpsl_object(
        &mut self,
        source: &str,
        rpsl_pk: &str,
        object_class: &str,
        origin: JournalEntryOrigin,
        source_serial: Option<i64>,
        protect_rpsl_name: bool,
    ) -> Result<bool> {
        self.check_write_permitted()?;
        self.flush_rpsl_object_writing_buffer()?;
        let Some(id) = query::id_by_key(&self.t, self.txn, source, object_class, rpsl_pk)? else {
            tracing::error!(
                "{}",
                messages::no_row_matched(&format!("{rpsl_pk}/{source}"))
            );
            return Ok(false);
        };
        let row = self.remove_row(id)?;
        self.record_operation(
            DatabaseOperation::Delete,
            &row.rpsl_pk,
            &row.source,
            &row.object_class,
            &row.object_text,
            origin,
            source_serial,
        )?;
        self.object_modified(&row.object_class, &row.source, row.prefix, Some(origin));

        if protect_rpsl_name && PROTECTED_NAME_OBJECT_CLASSES.contains(&object_class) {
            self.put_protected_name(&ProtectedNameRow {
                pk: Uuid::new_v4(),
                rpsl_pk: row.rpsl_pk.clone(),
                source: row.source.clone(),
                object_class: row.object_class.clone(),
                protected_name: row.rpsl_pk.clone(),
                created: self.txn_now,
            })?;
        }
        Ok(true)
    }

    /// `suspend_rpsl_object(pk_uuid)`: move the object to
    /// `rpsl_objects_suspended` and journal a deletion.
    pub fn suspend_rpsl_object(&mut self, pk: Uuid) -> Result<()> {
        self.check_write_permitted()?;
        self.flush_rpsl_object_writing_buffer()?;
        let Some(id) = query::id_by_uuid(&self.t, self.txn, &pk)? else {
            let pk_str = pk.to_string();
            tracing::error!("{}", messages::no_row_matched(&pk_str));
            return Err(StoreError::ValueError(messages::suspend_missing(&pk_str)));
        };
        let row = self.remove_row(id)?;
        let parsed = row.parsed_data.value();
        let mntners = match parsed.get("mnt-by") {
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect(),
            Some(serde_json::Value::String(s)) => vec![s.clone()],
            _ => return Err(StoreError::ValueError("'mnt-by'".to_owned())),
        };
        self.put_suspended_object(&SuspendedObjectRow {
            pk: Uuid::new_v4(),
            rpsl_pk: row.rpsl_pk.clone(),
            source: row.source.clone(),
            object_class: row.object_class.clone(),
            object_text: row.object_text.clone(),
            mntners,
            timestamp: self.txn_now,
            original_created: row.created,
            original_updated: row.updated,
        })?;
        self.record_operation(
            DatabaseOperation::Delete,
            &row.rpsl_pk,
            &row.source,
            &row.object_class,
            &row.object_text,
            JournalEntryOrigin::Suspension,
            None,
        )?;
        self.object_modified(
            &row.object_class,
            &row.source,
            row.prefix,
            Some(JournalEntryOrigin::Suspension),
        );
        Ok(())
    }

    /// `delete_suspended_rpsl_objects(pk_uuids)`
    pub fn delete_suspended_rpsl_objects(&mut self, pks: &[Uuid]) -> Result<()> {
        self.check_write_permitted()?;
        self.flush_rpsl_object_writing_buffer()?;
        for pk in pks {
            if let Some(b) = self.t.suspended.get(self.txn, pk.as_bytes())? {
                let row: SuspendedObjectRow = decode(b)?;
                for m in &row.mntners {
                    self.t
                        .suspended_mntner
                        .delete(self.txn, &suspended_mntner_key(m, pk))?;
                }
                self.t.suspended.delete(self.txn, pk.as_bytes())?;
            }
        }
        Ok(())
    }

    /// `insert_roa_object(ip_version, prefix_str, asn, max_length,
    /// trust_anchor)`: buffered until commit, as v4's COPY is.
    pub fn insert_roa_object(
        &mut self,
        ip_version: u8,
        prefix: IpPrefix,
        asn: i64,
        max_length: i64,
        trust_anchor: &str,
    ) -> Result<()> {
        self.check_write_permitted()?;
        self.roa_buffer.push(RoaRow {
            pk: Uuid::new_v4(),
            prefix,
            asn,
            max_length,
            trust_anchor: Some(trust_anchor.to_owned()),
            ip_version,
            created: self.txn_now,
        });
        Ok(())
    }

    fn flush_roa_writing_buffer(&mut self) -> Result<()> {
        for roa in std::mem::take(&mut self.roa_buffer) {
            let key = roa_key(&roa);
            if self.t.roa.get(self.txn, &key)?.is_some() {
                return Err(StoreError::UniqueViolation(messages::roa_conflict(
                    &roa.prefix.to_string(),
                    roa.asn,
                    roa.max_length,
                    roa.trust_anchor.as_deref().unwrap_or(""),
                )));
            }
            self.put_roa(&roa)?;
        }
        Ok(())
    }

    /// `delete_all_roa_objects()`
    pub fn delete_all_roa_objects(&mut self) -> Result<()> {
        self.check_write_permitted()?;
        self.roa_buffer.clear();
        self.t.roa.clear(self.txn)?;
        Ok(())
    }

    /// `update_rpki_status(rpsl_objs_now_valid, rpsl_objs_now_invalid,
    /// rpsl_objs_now_not_found)`. Objects moving into or out of visibility
    /// get journal entries with origin `rpki_status`.
    pub fn update_rpki_status(
        &mut self,
        now_valid: &[StatusChange<RpkiStatus>],
        now_invalid: &[StatusChange<RpkiStatus>],
        now_not_found: &[StatusChange<RpkiStatus>],
    ) -> Result<()> {
        self.check_write_permitted()?;
        for (list, status) in [
            (now_valid, RpkiStatus::Valid),
            (now_invalid, RpkiStatus::Invalid),
            (now_not_found, RpkiStatus::NotFound),
        ] {
            for c in list {
                self.modify_by_uuid(&c.pk, |r| r.rpki_status = status)?;
            }
        }
        let mut becoming = Vec::new();
        for c in now_valid.iter().chain(now_not_found) {
            becoming.push((c, true));
        }
        for c in now_invalid {
            becoming.push((c, false));
        }
        for (c, to_visible) in becoming {
            let Some(row) = self.row_by_uuid(&c.pk)? else {
                continue;
            };
            let before = object_is_visible(
                c.old_status,
                row.scopefilter_status,
                row.route_preference_status,
            );
            let now = object_is_visible(
                c.new_status,
                row.scopefilter_status,
                row.route_preference_status,
            );
            if to_visible && now && !before {
                self.journal_status_change(
                    &row,
                    DatabaseOperation::AddOrUpdate,
                    JournalEntryOrigin::RpkiStatus,
                )?;
            } else if !to_visible && !now && before {
                self.journal_status_change(
                    &row,
                    DatabaseOperation::Delete,
                    JournalEntryOrigin::RpkiStatus,
                )?;
            }
        }
        Ok(())
    }

    /// `update_scopefilter_status(rpsl_objs_now_in_scope,
    /// rpsl_objs_now_out_scope_as, rpsl_objs_now_out_scope_prefix)`.
    ///
    /// As in v4, the status update matches on the RPSL primary key, so every
    /// object with that primary key (in any source or class) gets the new
    /// status; the journal entries are for the objects passed in.
    pub fn update_scopefilter_status(
        &mut self,
        now_in_scope: &[StatusChange<ScopeFilterStatus>],
        now_out_scope_as: &[StatusChange<ScopeFilterStatus>],
        now_out_scope_prefix: &[StatusChange<ScopeFilterStatus>],
    ) -> Result<()> {
        self.check_write_permitted()?;
        for (list, status) in [
            (now_in_scope, ScopeFilterStatus::InScope),
            (now_out_scope_as, ScopeFilterStatus::OutScopeAs),
            (now_out_scope_prefix, ScopeFilterStatus::OutScopePrefix),
        ] {
            let pks: BTreeSet<&str> = list.iter().map(|c| c.rpsl_pk.as_str()).collect();
            for rpsl_pk in pks {
                for id in index::ids_by_rpsl_pk(&self.t, self.txn, rpsl_pk)? {
                    self.modify_by_id(id, |r| r.scopefilter_status = status)?;
                }
            }
        }
        for c in now_in_scope {
            let Some(row) = self.row_by_uuid(&c.pk)? else {
                continue;
            };
            let before =
                object_is_visible(row.rpki_status, c.old_status, row.route_preference_status);
            let now = object_is_visible(row.rpki_status, c.new_status, row.route_preference_status);
            if now && !before {
                self.journal_status_change(
                    &row,
                    DatabaseOperation::AddOrUpdate,
                    JournalEntryOrigin::ScopeFilter,
                )?;
            }
        }
        for c in now_out_scope_as.iter().chain(now_out_scope_prefix) {
            let Some(row) = self.row_by_uuid(&c.pk)? else {
                continue;
            };
            let before =
                object_is_visible(row.rpki_status, c.old_status, row.route_preference_status);
            let now = object_is_visible(row.rpki_status, c.new_status, row.route_preference_status);
            if !now && before {
                self.journal_status_change(
                    &row,
                    DatabaseOperation::Delete,
                    JournalEntryOrigin::ScopeFilter,
                )?;
            }
        }
        Ok(())
    }

    /// `update_route_preference_status(rpsl_objs_now_visible,
    /// rpsl_objs_now_suppressed)`, by row UUID.
    pub fn update_route_preference_status(
        &mut self,
        now_visible: &[Uuid],
        now_suppressed: &[Uuid],
    ) -> Result<()> {
        self.check_write_permitted()?;
        for (list, op) in [
            (now_visible, DatabaseOperation::AddOrUpdate),
            (now_suppressed, DatabaseOperation::Delete),
        ] {
            for pk in list {
                let Some(row) = self.row_by_uuid(pk)? else {
                    continue;
                };
                if object_is_visible(
                    row.rpki_status,
                    row.scopefilter_status,
                    RoutePreferenceStatus::Visible,
                ) {
                    self.journal_status_change(&row, op, JournalEntryOrigin::RoutePreference)?;
                }
            }
        }
        for pk in now_visible {
            self.modify_by_uuid(pk, |r| {
                r.route_preference_status = RoutePreferenceStatus::Visible
            })?;
        }
        for pk in now_suppressed {
            self.modify_by_uuid(pk, |r| {
                r.route_preference_status = RoutePreferenceStatus::Suppressed
            })?;
        }
        Ok(())
    }

    fn journal_status_change(
        &mut self,
        row: &RpslObjectRow,
        op: DatabaseOperation,
        origin: JournalEntryOrigin,
    ) -> Result<()> {
        self.record_operation(
            op,
            &row.rpsl_pk,
            &row.source,
            &row.object_class,
            &row.object_text,
            origin,
            None,
        )?;
        self.object_modified(&row.object_class, &row.source, row.prefix, Some(origin));
        Ok(())
    }

    /// `delete_journal_entries_before_date(timestamp, source)`
    pub fn delete_journal_entries_before_date(
        &mut self,
        before: Timestamp,
        source: &str,
    ) -> Result<()> {
        self.check_write_permitted()?;
        self.flush_rpsl_object_writing_buffer()?;
        let p = source_prefix(source);
        let mut doomed = Vec::new();
        for item in self.t.journal.prefix_iter(self.txn, &p)? {
            let (k, v) = item?;
            let e: JournalEntryRef<'_> = decode(v)?;
            if e.timestamp < before {
                doomed.push((k.to_vec(), e.serial_global));
            }
        }
        for (k, g) in doomed {
            self.t.journal.delete(self.txn, &k)?;
            self.t.journal_global.delete(self.txn, &serial_bytes(g))?;
        }
        Ok(())
    }

    /// `delete_all_rpsl_objects_with_journal(source, journal_guaranteed_empty)`:
    /// remove every object of the source, its journal (unless guaranteed
    /// empty) and its `database_status` row. No journal entries are made.
    pub fn delete_all_rpsl_objects_with_journal(
        &mut self,
        source: &str,
        journal_guaranteed_empty: bool,
    ) -> Result<()> {
        self.check_write_permitted()?;
        self.flush_rpsl_object_writing_buffer()?;
        let p = source_prefix(source);
        let mut ids = Vec::new();
        for item in self.t.objects_key.prefix_iter(self.txn, &p)? {
            let (_, v) = item?;
            ids.push(u64::from_be_bytes(
                v.try_into().map_err(|_| StoreError::Corrupt("object id"))?,
            ));
        }
        for id in ids {
            self.remove_row(id)?;
        }
        if !journal_guaranteed_empty {
            self.delete_journal_of_source(source)?;
        }
        self.t.status.delete(self.txn, source.as_bytes())?;
        self.changed.object_classes.extend(
            crate::write::ALL_OBJECT_CLASSES
                .iter()
                .map(|c| (*c).to_owned()),
        );
        Ok(())
    }

    fn delete_journal_of_source(&mut self, source: &str) -> Result<()> {
        let p = source_prefix(source);
        let mut doomed = Vec::new();
        for item in self.t.journal.prefix_iter(self.txn, &p)? {
            let (k, v) = item?;
            let e: JournalEntryRef<'_> = decode(v)?;
            doomed.push((k.to_vec(), e.serial_global));
        }
        for (k, g) in doomed {
            self.t.journal.delete(self.txn, &k)?;
            self.t.journal_global.delete(self.txn, &serial_bytes(g))?;
        }
        Ok(())
    }

    /// `set_force_reload(source)`
    pub fn set_force_reload(&mut self, source: &str) -> Result<()> {
        self.check_write_permitted()?;
        let synchronised_serials = self.settings.serials_synchronisable(source);
        if let Some(mut st) = query::status(&self.t, self.txn, source)? {
            st.force_reload = true;
            st.synchronised_serials = synchronised_serials;
            st.serial_oldest_seen = None;
            st.serial_newest_seen = None;
            st.updated = self.txn_now;
            self.put_database_status(&st)?;
        }
        tracing::info!(
            "{}",
            messages::force_reload_set(source, synchronised_serials)
        );
        Ok(())
    }

    /// `record_serial_newest_mirror(source, serial)`
    pub fn record_serial_newest_mirror(&mut self, source: &str, serial: i64) -> Result<()> {
        self.check_write_permitted()?;
        self.tracker.sources_seen.insert(source.to_owned());
        self.tracker
            .newest_mirror_serials
            .insert(source.to_owned(), serial);
        Ok(())
    }

    /// `record_serial_seen(source, serial)`
    pub fn record_serial_seen(&mut self, source: &str, serial: i64) -> Result<()> {
        self.check_write_permitted()?;
        self.tracker.sources_seen.insert(source.to_owned());
        self.tracker
            .new_serials_per_source
            .entry(source.to_owned())
            .or_default()
            .insert(serial);
        Ok(())
    }

    /// `record_mirror_error(source, error)`
    pub fn record_mirror_error(&mut self, source: &str, error: &str) -> Result<()> {
        self.check_write_permitted()?;
        self.tracker.sources_seen.insert(source.to_owned());
        self.tracker
            .mirroring_error
            .insert(source.to_owned(), error.to_owned());
        Ok(())
    }

    /// `record_serial_exported(source, serial)`
    pub fn record_serial_exported(&mut self, source: &str, serial: i64) -> Result<()> {
        self.check_write_permitted()?;
        self.tracker.sources_seen.insert(source.to_owned());
        self.tracker
            .exported_serials
            .insert(source.to_owned(), serial);
        Ok(())
    }

    /// `record_nrtm4_client_status(source, status)`
    pub fn record_nrtm4_client_status(
        &mut self,
        source: &str,
        status: Nrtm4ClientStatus,
    ) -> Result<()> {
        self.check_write_permitted()?;
        self.tracker.sources_seen.insert(source.to_owned());
        self.tracker
            .nrtm4_client_status
            .insert(source.to_owned(), status);
        Ok(())
    }

    /// `record_nrtm4_server_status(source, status)`
    pub fn record_nrtm4_server_status(
        &mut self,
        source: &str,
        status: Nrtm4ServerStatus,
    ) -> Result<()> {
        self.check_write_permitted()?;
        self.tracker.sources_seen.insert(source.to_owned());
        self.tracker
            .nrtm4_server_status
            .insert(source.to_owned(), status);
        Ok(())
    }

    /// `is_serial_synchronised(dh, source)`, cached for the transaction as
    /// v4's tracker caches it.
    pub fn is_serial_synchronised(&mut self, source: &str) -> Result<bool> {
        if let Some(v) = self.tracker.is_serial_synchronised.get(source) {
            return Ok(*v);
        }
        let db_status = query::status(&self.t, self.txn, source)?
            .map(|s| s.synchronised_serials)
            .unwrap_or(true);
        let v = db_status && self.settings.serials_synchronisable(source);
        self.tracker
            .is_serial_synchronised
            .insert(source.to_owned(), v);
        Ok(v)
    }

    // -----------------------------------------------------------------
    // DatabaseStatusTracker
    // -----------------------------------------------------------------

    /// `record_operation()`: journal a change if journaling is enabled and
    /// the source keeps a journal, assigning `serial_nrtm` as v4 does.
    #[allow(clippy::too_many_arguments)]
    pub fn record_operation(
        &mut self,
        operation: DatabaseOperation,
        rpsl_pk: &str,
        source: &str,
        object_class: &str,
        object_text: &str,
        origin: JournalEntryOrigin,
        source_serial: Option<i64>,
    ) -> Result<()> {
        self.tracker.sources_seen.insert(source.to_owned());
        self.tracker
            .sources_rpsl_data_updated
            .insert(source.to_owned());
        if !(self.journaling_enabled && self.settings.source(source).keep_journal) {
            return Ok(());
        }
        let serial_nrtm = if self.is_serial_synchronised(source)? {
            source_serial.ok_or_else(|| {
                StoreError::NotNullViolation(messages::JOURNAL_SERIAL_NULL.to_owned())
            })?
        } else if let Some(max) = self
            .tracker
            .new_serials_per_source
            .get(source)
            .and_then(|s| s.last())
        {
            max + 1
        } else {
            // COALESCE(MAX(serial_nrtm), MAX(serial_newest_seen), 0) + 1
            // FROM database_status LEFT OUTER JOIN rpsl_database_journal
            // WHERE database_status.source = source
            match query::status(&self.t, self.txn, source)? {
                None => 1,
                Some(st) => {
                    let max_journal =
                        query::journal_serial_bounds(&self.t, self.txn, source)?.map(|(_, h)| h);
                    max_journal.or(st.serial_newest_seen).unwrap_or(0) + 1
                }
            }
        };
        let key = query::journal_key(source, serial_nrtm);
        if self.t.journal.get(self.txn, &key)?.is_some() {
            return Err(StoreError::UniqueViolation(
                messages::journal_serial_conflict(source, serial_nrtm),
            ));
        }
        let serial_global = self.next_serial_global()?;
        let entry = JournalEntryRef {
            pk: Uuid::new_v4(),
            serial_global,
            rpsl_pk,
            source,
            origin,
            serial_nrtm,
            operation,
            object_class,
            object_text,
            timestamp: Timestamp::now(),
        };
        self.t.journal.put(self.txn, &key, &encode(&entry)?)?;
        self.t
            .journal_global
            .put(self.txn, &serial_bytes(serial_global), &key)?;
        self.tracker
            .new_serials_per_source
            .entry(source.to_owned())
            .or_default()
            .insert(serial_nrtm);
        self.changed
            .sources_with_new_serials
            .insert(source.to_owned());
        Ok(())
    }

    fn next_serial_global(&mut self) -> Result<i64> {
        let next = query::serial_global_last(&self.t, self.txn)? + 1;
        self.t
            .meta
            .put(self.txn, META_SERIAL_GLOBAL_LAST, &serial_bytes(next))?;
        Ok(next)
    }

    /// Commit-time work: flush buffers, run the route preference hook, and
    /// `finalise_transaction()`. Called by the writer before committing.
    pub(crate) fn finish(&mut self) -> Result<ChangedObjects> {
        self.flush_rpsl_object_writing_buffer()?;
        self.flush_roa_writing_buffer()?;
        self.finalise_transaction()?;
        if !self.changed.prefixes_for_routepref.is_empty()
            && let Some(hook) = self.routepref_hook
        {
            let prefixes: Vec<IpPrefix> = self
                .changed
                .prefixes_for_routepref
                .iter()
                .copied()
                .collect();
            // v4 runs this in `pre_commit()`, after `finalise_transaction()`,
            // so journal entries it makes are not reflected in
            // `database_status` until a later transaction.
            hook(self, &prefixes)?;
        }
        Ok(std::mem::take(&mut self.changed))
    }

    fn finalise_transaction(&mut self) -> Result<()> {
        let now = Timestamp::now();
        let sources_seen: Vec<String> = self.tracker.sources_seen.iter().cloned().collect();
        for source in &sources_seen {
            let sync = self.is_serial_synchronised(source)?;
            let st = match query::status(&self.t, self.txn, source)? {
                Some(mut st) => {
                    st.force_reload = false;
                    st.synchronised_serials = sync;
                    st
                }
                None => {
                    let mut st = DatabaseStatus::new(source, self.txn_now);
                    st.rpsl_data_updated = now;
                    st.synchronised_serials = sync;
                    st
                }
            };
            self.put_database_status(&st)?;
        }

        let txn_now = self.txn_now;
        for source in self.tracker.sources_rpsl_data_updated.clone() {
            self.update_status(&source, |st| {
                st.rpsl_data_updated = now;
                st.updated = txn_now;
            })?;
        }

        for (source, serials) in self.tracker.new_serials_per_source.clone() {
            let bounds = query::journal_serial_bounds(&self.t, self.txn, &source)?;
            let (oldest_journal, newest_journal) = (bounds.map(|b| b.0), bounds.map(|b| b.1));
            let (min_s, max_s) = (serials.first().copied(), serials.last().copied());
            self.update_status(&source, |st| {
                // PostgreSQL's LEAST/GREATEST ignore NULLs.
                st.serial_oldest_seen = [st.serial_oldest_seen, oldest_journal, min_s]
                    .into_iter()
                    .flatten()
                    .min();
                st.serial_newest_seen = [st.serial_newest_seen, newest_journal, max_s]
                    .into_iter()
                    .flatten()
                    .max();
                st.serial_oldest_journal = oldest_journal;
                st.serial_newest_journal = newest_journal;
                st.rpsl_data_updated = now;
                st.updated = txn_now;
            })?;
        }

        for (source, error) in self.tracker.mirroring_error.clone() {
            self.update_status(&source, |st| {
                st.last_error = Some(error.clone());
                st.last_error_timestamp = Some(now);
                st.updated = txn_now;
            })?;
        }
        for (source, serial) in self.tracker.newest_mirror_serials.clone() {
            self.update_status(&source, |st| {
                st.serial_newest_mirror = Some(serial);
                st.rpsl_data_updated = now;
                st.updated = txn_now;
            })?;
        }
        for (source, serial) in self.tracker.exported_serials.clone() {
            self.update_status(&source, |st| {
                st.serial_last_export = Some(serial);
                st.updated = txn_now;
            })?;
        }
        for (source, s) in self.tracker.nrtm4_client_status.clone() {
            self.update_status(&source, |st| {
                st.nrtm4_client_session_id = s.session_id;
                st.nrtm4_client_version = s.version;
                st.nrtm4_client_current_key = s.current_key.clone();
                st.nrtm4_client_next_key = s.next_key.clone();
                st.nrtm4_client_previous_file_hashes = s.previous_file_hashes.clone();
                st.updated = txn_now;
            })?;
        }
        for (source, s) in self.tracker.nrtm4_server_status.clone() {
            self.update_status(&source, |st| {
                st.nrtm4_server_session_id = s.session_id;
                st.nrtm4_server_version = s.version;
                st.nrtm4_server_last_update_notification_file_update =
                    s.last_update_notification_file_update;
                st.nrtm4_server_last_snapshot_version = s.last_snapshot_version;
                st.nrtm4_server_last_snapshot_global_serial = s.last_snapshot_global_serial;
                st.nrtm4_server_last_snapshot_filename = s.last_snapshot_filename.clone();
                st.nrtm4_server_last_snapshot_timestamp = s.last_snapshot_timestamp;
                st.nrtm4_server_last_snapshot_hash = s.last_snapshot_hash.clone();
                st.nrtm4_server_previous_deltas = s.previous_deltas.clone();
                st.updated = txn_now;
            })?;
        }
        Ok(())
    }

    fn update_status(&mut self, source: &str, f: impl FnOnce(&mut DatabaseStatus)) -> Result<()> {
        if let Some(mut st) = query::status(&self.t, self.txn, source)? {
            f(&mut st);
            self.put_database_status(&st)?;
        }
        Ok(())
    }

    fn object_modified(
        &mut self,
        object_class: &str,
        source: &str,
        prefix: Option<IpPrefix>,
        origin: Option<JournalEntryOrigin>,
    ) {
        self.changed.object_classes.insert(object_class.to_owned());
        if let Some(prefix) = prefix
            && RPKI_RELEVANT_OBJECT_CLASSES.contains(&object_class)
            && origin != Some(JournalEntryOrigin::RoutePreference)
            && source != RPKI_IRR_PSEUDO_SOURCE
        {
            self.changed.prefixes_for_routepref.insert(prefix);
        }
    }

    // -----------------------------------------------------------------
    // Row storage
    // -----------------------------------------------------------------

    fn alloc_object_id(&mut self) -> Result<u64> {
        let next = match self.t.meta.get(self.txn, META_NEXT_OBJECT_ID)? {
            Some(b) => u64::from_be_bytes(b.try_into().map_err(|_| StoreError::Corrupt("meta"))?),
            None => 1,
        };
        self.t
            .meta
            .put(self.txn, META_NEXT_OBJECT_ID, &(next + 1).to_be_bytes())?;
        Ok(next)
    }

    /// Insert or replace a row by (source, class, rpsl_pk), maintaining
    /// every index. Returns the internal id.
    fn store_row(&mut self, row: &RpslObjectRef<'_>) -> Result<u64> {
        let key = object_key(row.source, row.object_class, row.rpsl_pk);
        let existing = match self.t.objects_key.get(self.txn, &key)? {
            Some(b) => Some(u64::from_be_bytes(
                b.try_into().map_err(|_| StoreError::Corrupt("object id"))?,
            )),
            None => None,
        };
        // A row with this UUID under another key goes: the UUID is unique.
        if let Some(other) = query::id_by_uuid(&self.t, self.txn, &row.pk)?
            && Some(other) != existing
        {
            self.remove_row(other)?;
        }
        let id = match existing {
            Some(id) => {
                let old = self
                    .t
                    .objects
                    .get(self.txn, &id_bytes(id))?
                    .map(|b| b.to_vec())
                    .ok_or(StoreError::Corrupt("missing object"))?;
                let old: RpslObjectRef<'_> = decode(&old)?;
                index::remove(self.txn, &self.t, &old, id)?;
                if old.pk != row.pk {
                    self.t.objects_uuid.delete(self.txn, old.pk.as_bytes())?;
                }
                id
            }
            None => {
                let id = self.alloc_object_id()?;
                self.t.objects_key.put(self.txn, &key, &id_bytes(id))?;
                id
            }
        };
        self.t.objects.put(self.txn, &id_bytes(id), &encode(row)?)?;
        self.t
            .objects_uuid
            .put(self.txn, row.pk.as_bytes(), &id_bytes(id))?;
        index::add(self.txn, &self.t, row, id)?;
        Ok(id)
    }

    /// Remove a row and its index entries, returning it.
    fn remove_row(&mut self, id: u64) -> Result<RpslObjectRow> {
        let bytes = self
            .t
            .objects
            .get(self.txn, &id_bytes(id))?
            .map(|b| b.to_vec())
            .ok_or(StoreError::Corrupt("missing object"))?;
        let r: RpslObjectRef<'_> = decode(&bytes)?;
        index::remove(self.txn, &self.t, &r, id)?;
        self.t
            .objects_key
            .delete(self.txn, &object_key(r.source, r.object_class, r.rpsl_pk))?;
        self.t.objects_uuid.delete(self.txn, r.pk.as_bytes())?;
        self.t.objects.delete(self.txn, &id_bytes(id))?;
        Ok(r.to_row())
    }

    fn row_by_uuid(&self, pk: &Uuid) -> Result<Option<RpslObjectRow>> {
        let Some(id) = query::id_by_uuid(&self.t, self.txn, pk)? else {
            return Ok(None);
        };
        Ok(query::object_by_id(&self.t, self.txn, id)?.map(|r| r.to_row()))
    }

    fn modify_by_uuid(&mut self, pk: &Uuid, f: impl FnOnce(&mut RpslObjectRow)) -> Result<()> {
        if let Some(id) = query::id_by_uuid(&self.t, self.txn, pk)? {
            self.modify_by_id(id, f)?;
        }
        Ok(())
    }

    fn modify_by_id(&mut self, id: u64, f: impl FnOnce(&mut RpslObjectRow)) -> Result<()> {
        let Some(mut row) = query::object_by_id(&self.t, self.txn, id)?.map(|r| r.to_row()) else {
            return Ok(());
        };
        f(&mut row);
        self.store_row(&RpslObjectRef::from_row(&row))?;
        Ok(())
    }

    // -----------------------------------------------------------------
    // Raw rows: the v4 importer's API. No journaling, no status tracking,
    // no buffering; each call is an idempotent upsert on the table's
    // natural key.
    // -----------------------------------------------------------------

    /// Upsert an `rpsl_objects` row by (source, object_class, rpsl_pk),
    /// keeping its UUID and timestamps exactly.
    pub fn put_rpsl_object(&mut self, row: &RpslObjectRow) -> Result<()> {
        self.check_write_permitted()?;
        self.store_row(&RpslObjectRef::from_row(row))?;
        Ok(())
    }

    /// Upsert an `rpsl_database_journal` row by (source, serial_nrtm). The
    /// `serial_global` sequence moves past the entry's serial if needed.
    pub fn put_journal_entry(&mut self, e: &JournalEntry) -> Result<()> {
        self.check_write_permitted()?;
        let key = query::journal_key(&e.source, e.serial_nrtm);
        if let Some(b) = self.t.journal.get(self.txn, &key)? {
            let old: JournalEntryRef<'_> = decode(b)?;
            let g = old.serial_global;
            self.t.journal_global.delete(self.txn, &serial_bytes(g))?;
        }
        // serial_global is unique: drop whatever entry held it.
        if let Some(other) = self
            .t
            .journal_global
            .get(self.txn, &serial_bytes(e.serial_global))?
        {
            let other = other.to_vec();
            if other != key {
                self.t.journal.delete(self.txn, &other)?;
            }
        }
        self.t
            .journal
            .put(self.txn, &key, &encode(&JournalEntryRef::from_entry(e))?)?;
        self.t
            .journal_global
            .put(self.txn, &serial_bytes(e.serial_global), &key)?;
        self.set_serial_global_last_value(e.serial_global)?;
        Ok(())
    }

    /// Move the `serial_global` sequence to at least `last_value` (v4's
    /// `rpsl_database_journal_serial_global_seq.last_value`), so new
    /// entries continue after it.
    pub fn set_serial_global_last_value(&mut self, last_value: i64) -> Result<()> {
        self.check_write_permitted()?;
        if last_value > query::serial_global_last(&self.t, self.txn)? {
            self.t
                .meta
                .put(self.txn, META_SERIAL_GLOBAL_LAST, &serial_bytes(last_value))?;
        }
        Ok(())
    }

    /// Upsert a `database_status` row by source.
    pub fn put_database_status(&mut self, row: &DatabaseStatus) -> Result<()> {
        self.check_write_permitted()?;
        self.t
            .status
            .put(self.txn, row.source.as_bytes(), &encode(row)?)?;
        Ok(())
    }

    /// Delete a `database_status` row.
    pub fn delete_database_status(&mut self, source: &str) -> Result<bool> {
        self.check_write_permitted()?;
        Ok(self.t.status.delete(self.txn, source.as_bytes())?)
    }

    /// Upsert a `roa_object` row by (prefix, asn, max_length, trust_anchor).
    pub fn put_roa(&mut self, row: &RoaRow) -> Result<()> {
        self.check_write_permitted()?;
        let v = RoaValue {
            pk: row.pk,
            created: row.created,
        };
        self.t.roa.put(self.txn, &roa_key(row), &encode(&v)?)?;
        Ok(())
    }

    /// Upsert an `rpsl_objects_suspended` row by `pk`.
    pub fn put_suspended_object(&mut self, row: &SuspendedObjectRow) -> Result<()> {
        self.check_write_permitted()?;
        if let Some(b) = self.t.suspended.get(self.txn, row.pk.as_bytes())? {
            let old: SuspendedObjectRow = decode(b)?;
            for m in &old.mntners {
                self.t
                    .suspended_mntner
                    .delete(self.txn, &suspended_mntner_key(m, &old.pk))?;
            }
        }
        self.t
            .suspended
            .put(self.txn, row.pk.as_bytes(), &encode(row)?)?;
        for m in &row.mntners {
            self.t
                .suspended_mntner
                .put(self.txn, &suspended_mntner_key(m, &row.pk), &[])?;
        }
        Ok(())
    }

    /// Upsert a `protected_rpsl_name` row by `pk`.
    pub fn put_protected_name(&mut self, row: &ProtectedNameRow) -> Result<()> {
        self.check_write_permitted()?;
        if let Some(b) = self.t.protected_name.get(self.txn, row.pk.as_bytes())? {
            let old: ProtectedNameRow = decode(b)?;
            self.t
                .protected_name_idx
                .delete(self.txn, &protected_name_key(&old))?;
        }
        self.t
            .protected_name
            .put(self.txn, row.pk.as_bytes(), &encode(row)?)?;
        self.t
            .protected_name_idx
            .put(self.txn, &protected_name_key(row), &[])?;
        Ok(())
    }

    /// Upsert a `setting` row by name.
    pub fn put_setting(&mut self, row: &SettingRow) -> Result<()> {
        self.check_write_permitted()?;
        self.t
            .setting
            .put(self.txn, row.name.as_bytes(), &encode(row)?)?;
        Ok(())
    }

    /// Upsert an `auth_user` row by `pk`.
    pub fn put_auth_user(&mut self, row: &AuthUserRow) -> Result<()> {
        self.check_write_permitted()?;
        self.t
            .auth_user
            .put(self.txn, row.pk.as_bytes(), &encode(row)?)?;
        Ok(())
    }

    /// Upsert an `auth_permission` row by `pk`.
    pub fn put_auth_permission(&mut self, row: &AuthPermissionRow) -> Result<()> {
        self.check_write_permitted()?;
        self.t
            .auth_permission
            .put(self.txn, row.pk.as_bytes(), &encode(row)?)?;
        Ok(())
    }

    /// Upsert an `auth_mntner` row by `pk`.
    pub fn put_auth_mntner(&mut self, row: &AuthMntnerRow) -> Result<()> {
        self.check_write_permitted()?;
        self.t
            .auth_mntner
            .put(self.txn, row.pk.as_bytes(), &encode(row)?)?;
        Ok(())
    }

    /// Upsert an `auth_api_token` row by `pk`.
    pub fn put_auth_api_token(&mut self, row: &AuthApiTokenRow) -> Result<()> {
        self.check_write_permitted()?;
        if let Some(b) = self.t.auth_api_token.get(self.txn, row.pk.as_bytes())? {
            let old: AuthApiTokenRow = decode(b)?;
            if let Some(tok) = old.token {
                self.t.api_token_idx.delete(self.txn, tok.as_bytes())?;
            }
        }
        self.t
            .auth_api_token
            .put(self.txn, row.pk.as_bytes(), &encode(row)?)?;
        if let Some(tok) = row.token {
            self.t
                .api_token_idx
                .put(self.txn, tok.as_bytes(), row.pk.as_bytes())?;
        }
        Ok(())
    }

    /// Upsert an `auth_webauthn` row by `pk`.
    pub fn put_auth_webauthn(&mut self, row: &AuthWebAuthnRow) -> Result<()> {
        self.check_write_permitted()?;
        self.t
            .auth_webauthn
            .put(self.txn, row.pk.as_bytes(), &encode(row)?)?;
        Ok(())
    }

    /// Upsert a `change_log` row by `pk`.
    pub fn put_change_log(&mut self, row: &ChangeLogRow) -> Result<()> {
        self.check_write_permitted()?;
        self.t
            .change_log
            .put(self.txn, row.pk.as_bytes(), &encode(row)?)?;
        Ok(())
    }

    /// Empty every data table (not `meta`), for a clean re-import.
    pub fn clear_all_data(&mut self) -> Result<()> {
        self.check_write_permitted()?;
        let t = self.t;
        for table in [
            t.objects,
            t.objects_key,
            t.objects_uuid,
            t.idx_rpsl_pk,
            t.idx_lookup,
            t.set_members,
            t.ip4_range,
            t.ip4_cover,
            t.ip6_range,
            t.ip6_cover,
            t.asn_range,
            t.asn_cover,
            t.route_origin,
            t.journal,
            t.journal_global,
            t.status,
            t.roa,
            t.suspended,
            t.suspended_mntner,
            t.protected_name,
            t.protected_name_idx,
            t.setting,
            t.auth_user,
            t.auth_permission,
            t.auth_mntner,
            t.auth_api_token,
            t.api_token_idx,
            t.auth_webauthn,
            t.change_log,
        ] {
            table.clear(self.txn)?;
        }
        self.t.meta.delete(self.txn, META_SERIAL_GLOBAL_LAST)?;
        Ok(())
    }

    /// Accept a pre-built JSON document for `parsed_data` and similar
    /// columns, canonicalising it.
    pub fn json(text: &str) -> Result<Json> {
        Json::canonical(text).map_err(|e| StoreError::ValueError(e.to_string()))
    }
}

/// Every RPSL object class (`OBJECT_CLASS_MAPPING`).
pub const ALL_OBJECT_CLASSES: &[&str] = &[
    "as-block",
    "as-set",
    "aut-num",
    "domain",
    "filter-set",
    "inet-rtr",
    "inet6num",
    "inetnum",
    "key-cert",
    "mntner",
    "peering-set",
    "person",
    "role",
    "route",
    "route-set",
    "route6",
    "rtr-set",
];

pub(crate) fn roa_key(row: &RoaRow) -> Vec<u8> {
    let mut k = Vec::new();
    k.push(row.ip_version);
    let width = if row.prefix.addr.is_ipv4() { 4 } else { 16 };
    crate::keys::push_uint(&mut k, row.prefix.first(), width);
    k.push(row.prefix.len);
    k.extend_from_slice(&serial_bytes(row.asn));
    k.extend_from_slice(&serial_bytes(row.max_length));
    match &row.trust_anchor {
        None => k.push(0),
        Some(ta) => {
            k.push(1);
            push_str(&mut k, ta.as_bytes());
        }
    }
    k
}

pub(crate) fn suspended_mntner_key(mntner: &str, pk: &Uuid) -> Vec<u8> {
    let mut k = Vec::new();
    push_str(&mut k, mntner.as_bytes());
    k.extend_from_slice(pk.as_bytes());
    k
}

pub(crate) fn protected_name_key(row: &ProtectedNameRow) -> Vec<u8> {
    let mut k = Vec::new();
    push_str(&mut k, row.source.as_bytes());
    push_str(&mut k, row.protected_name.as_bytes());
    k.extend_from_slice(row.pk.as_bytes());
    k
}
