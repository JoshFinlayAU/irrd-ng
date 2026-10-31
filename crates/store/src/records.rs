//! Stored record layouts (postcard). A change to any of these is an on-disk
//! format change and needs a schema version bump and a migration.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::model::{
    DatabaseOperation, IpPrefix, JournalEntry, JournalEntryOrigin, Json, RoutePreferenceStatus,
    RpkiStatus, RpslObjectRow, ScopeFilterStatus, Timestamp, Uuid,
};

/// An `rpsl_objects` row as stored, borrowing its strings from the page.
///
/// Reading one is zero-copy: the strings point into the LMDB map for as
/// long as the read transaction lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpslObjectRef<'a> {
    /// `pk`
    pub pk: Uuid,
    /// `rpsl_pk`
    pub rpsl_pk: &'a str,
    /// `source`
    pub source: &'a str,
    /// `object_class`
    pub object_class: &'a str,
    /// `parsed_data`, canonical JSON text.
    pub parsed_data: &'a str,
    /// `object_text`, verbatim.
    pub object_text: &'a str,
    /// `ip_version`
    pub ip_version: Option<u8>,
    /// `ip_first`
    pub ip_first: Option<IpAddr>,
    /// `ip_last`
    pub ip_last: Option<IpAddr>,
    /// `prefix_length`
    pub prefix_length: Option<u32>,
    /// `prefix`
    pub prefix: Option<IpPrefix>,
    /// `asn_first`
    pub asn_first: Option<u32>,
    /// `asn_last`
    pub asn_last: Option<u32>,
    /// `rpki_status`
    pub rpki_status: RpkiStatus,
    /// `scopefilter_status`
    pub scopefilter_status: ScopeFilterStatus,
    /// `route_preference_status`
    pub route_preference_status: RoutePreferenceStatus,
    /// `created`
    pub created: Timestamp,
    /// `updated`
    pub updated: Timestamp,
}

impl<'a> RpslObjectRef<'a> {
    /// An owned copy.
    pub fn to_row(&self) -> RpslObjectRow {
        RpslObjectRow {
            pk: self.pk,
            rpsl_pk: self.rpsl_pk.to_owned(),
            source: self.source.to_owned(),
            object_class: self.object_class.to_owned(),
            parsed_data: Json(self.parsed_data.to_owned()),
            object_text: self.object_text.to_owned(),
            ip_version: self.ip_version,
            ip_first: self.ip_first,
            ip_last: self.ip_last,
            prefix_length: self.prefix_length,
            prefix: self.prefix,
            asn_first: self.asn_first,
            asn_last: self.asn_last,
            rpki_status: self.rpki_status,
            scopefilter_status: self.scopefilter_status,
            route_preference_status: self.route_preference_status,
            created: self.created,
            updated: self.updated,
        }
    }

    /// A borrowed view of an owned row.
    pub fn from_row(row: &'a RpslObjectRow) -> Self {
        RpslObjectRef {
            pk: row.pk,
            rpsl_pk: &row.rpsl_pk,
            source: &row.source,
            object_class: &row.object_class,
            parsed_data: &row.parsed_data.0,
            object_text: &row.object_text,
            ip_version: row.ip_version,
            ip_first: row.ip_first,
            ip_last: row.ip_last,
            prefix_length: row.prefix_length,
            prefix: row.prefix,
            asn_first: row.asn_first,
            asn_last: row.asn_last,
            rpki_status: row.rpki_status,
            scopefilter_status: row.scopefilter_status,
            route_preference_status: row.route_preference_status,
            created: row.created,
            updated: row.updated,
        }
    }

    /// Visible under v4's default suppression.
    pub fn is_visible(&self) -> bool {
        crate::model::object_is_visible(
            self.rpki_status,
            self.scopefilter_status,
            self.route_preference_status,
        )
    }

    /// `ip_size`, derived as v4 computes it.
    pub fn ip_size(&self) -> Option<String> {
        crate::model::ip_size(self.ip_first.as_ref(), self.ip_last.as_ref())
    }

    /// `parsed_data` parsed.
    pub fn parsed_data_value(&self) -> serde_json::Value {
        serde_json::from_str(self.parsed_data).unwrap_or(serde_json::Value::Null)
    }
}

/// An `rpsl_database_journal` row as stored (keyed by source and
/// `serial_nrtm`), borrowing its strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntryRef<'a> {
    /// `pk`
    pub pk: Uuid,
    /// `serial_global`
    pub serial_global: i64,
    /// `rpsl_pk`
    pub rpsl_pk: &'a str,
    /// `source`
    pub source: &'a str,
    /// `origin`
    pub origin: JournalEntryOrigin,
    /// `serial_nrtm`
    pub serial_nrtm: i64,
    /// `operation`
    pub operation: DatabaseOperation,
    /// `object_class`
    pub object_class: &'a str,
    /// `object_text`
    pub object_text: &'a str,
    /// `timestamp`
    pub timestamp: Timestamp,
}

impl JournalEntryRef<'_> {
    /// An owned copy.
    pub fn to_entry(&self) -> JournalEntry {
        JournalEntry {
            pk: self.pk,
            serial_global: self.serial_global,
            rpsl_pk: self.rpsl_pk.to_owned(),
            source: self.source.to_owned(),
            origin: self.origin,
            serial_nrtm: self.serial_nrtm,
            operation: self.operation,
            object_class: self.object_class.to_owned(),
            object_text: self.object_text.to_owned(),
            timestamp: self.timestamp,
        }
    }

    /// A borrowed view of an owned entry.
    pub fn from_entry(e: &JournalEntry) -> JournalEntryRef<'_> {
        JournalEntryRef {
            pk: e.pk,
            serial_global: e.serial_global,
            rpsl_pk: &e.rpsl_pk,
            source: &e.source,
            origin: e.origin,
            serial_nrtm: e.serial_nrtm,
            operation: e.operation,
            object_class: &e.object_class,
            object_text: &e.object_text,
            timestamp: e.timestamp,
        }
    }
}

/// The value of a `roa` table entry; the rest of the row is in the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RoaValue {
    pub(crate) pk: Uuid,
    pub(crate) created: Timestamp,
}

/// The forward set membership of an `as-set` or `route-set`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetMembers<'a> {
    /// `members` followed by `mp-members`, as in `parsed_data`.
    #[serde(borrow)]
    pub members: Vec<&'a str>,
    /// `mbrs-by-ref`.
    #[serde(borrow)]
    pub mbrs_by_ref: Vec<&'a str>,
}

pub(crate) fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_stdvec(v)
}

pub(crate) fn decode<'a, T: Deserialize<'a>>(b: &'a [u8]) -> Result<T, postcard::Error> {
    postcard::from_bytes(b)
}
