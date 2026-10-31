//! The data model: one Rust type per IRRd v4 table, with v4's column names.
//!
//! Every table v4 keeps in PostgreSQL (`irrd/storage/models.py` at 4.5.4,
//! alembic head) has a row type here holding every column, so the v4
//! importer can carry a database across without loss and the loaders can
//! write what v4's `DatabaseHandler` writes. Field names are v4's column
//! names; enum variants render as the PostgreSQL enum labels v4 stores
//! (the Python enum member names, e.g. `not_found`, `add_or_update`).
//!
//! Two columns are derived rather than stored, because v4 always computes
//! them from other columns of the same row:
//! - `rpsl_objects.ip_size` is `ip_last - ip_first + 1`
//!   ([`RpslObjectRow::ip_size`]);
//! - nothing else.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

pub use uuid::Uuid;

/// A `timestamp with time zone`: microseconds since the Unix epoch, UTC.
///
/// PostgreSQL keeps microsecond precision, so this holds exactly what v4's
/// columns hold. [`fmt::Display`] renders the canonical export form,
/// `2026-10-31T01:02:03.123456+00:00`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// The current time.
    pub fn now() -> Self {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Timestamp(i64::try_from(d.as_micros()).unwrap_or(i64::MAX))
    }

    /// From whole seconds since the epoch.
    pub fn from_unix_seconds(secs: i64) -> Self {
        Timestamp(secs.saturating_mul(1_000_000))
    }

    /// Whole seconds since the epoch, rounded down.
    pub fn unix_seconds(self) -> i64 {
        self.0.div_euclid(1_000_000)
    }

    /// Microseconds since the epoch.
    pub fn micros(self) -> i64 {
        self.0
    }

    /// Parse the canonical form written by [`fmt::Display`], and the common
    /// variations PostgreSQL and Python produce: a space instead of `T`,
    /// fewer or no fraction digits, and a `+00`, `+00:00`, `Z` or other
    /// numeric offset.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let b = s.as_bytes();
        if b.len() < 19 {
            return None;
        }
        let num = |r: std::ops::Range<usize>| -> Option<i64> {
            let t = s.get(r)?;
            if !t.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            t.parse().ok()
        };
        let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
        if b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b' ') {
            return None;
        }
        let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
        if b[13] != b':' || b[16] != b':' {
            return None;
        }
        let mut i = 19;
        let mut micros = 0i64;
        if b.get(i) == Some(&b'.') {
            i += 1;
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            let digits = &s[start..i];
            if digits.is_empty() {
                return None;
            }
            let mut padded: String = digits.chars().take(6).collect();
            while padded.len() < 6 {
                padded.push('0');
            }
            micros = padded.parse().ok()?;
        }
        let rest = &s[i..];
        let offset_secs = match rest {
            "" | "Z" | "z" => 0,
            _ => {
                let sign = match rest.as_bytes()[0] {
                    b'+' => 1,
                    b'-' => -1,
                    _ => return None,
                };
                let r = &rest[1..];
                let (h, m) = match r.len() {
                    2 => (r.parse::<i64>().ok()?, 0),
                    4 => (r[0..2].parse().ok()?, r[2..4].parse().ok()?),
                    5 if r.as_bytes()[2] == b':' => (r[0..2].parse().ok()?, r[3..5].parse().ok()?),
                    _ => return None,
                };
                sign * (h * 3600 + m * 60)
            }
        };
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
            return None;
        }
        let days = days_from_civil(year, month, day);
        let secs = days * 86400 + hour * 3600 + minute * 60 + second - offset_secs;
        Some(Timestamp(secs * 1_000_000 + micros))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.div_euclid(1_000_000);
        let micros = self.0.rem_euclid(1_000_000);
        let days = secs.div_euclid(86400);
        let rem = secs.rem_euclid(86400);
        let (y, m, d) = civil_from_days(days);
        write!(
            f,
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{micros:06}+00:00",
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        )
    }
}

/// Howard Hinnant's `days_from_civil`.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Howard Hinnant's `civil_from_days`.
pub(crate) fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A PostgreSQL `cidr` value: a network address and a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IpPrefix {
    /// The network address. Host bits are zero.
    pub addr: IpAddr,
    /// The prefix length.
    pub len: u8,
}

impl IpPrefix {
    /// A prefix, with host bits cleared. `None` if the length is too long
    /// for the address family.
    pub fn new(addr: IpAddr, len: u8) -> Option<Self> {
        let bits = ip_bits(&addr);
        if u32::from(len) > bits {
            return None;
        }
        let masked = ip_from_u128(ip_to_u128(&addr) & net_mask(len, bits), &addr);
        Some(IpPrefix { addr: masked, len })
    }

    /// Parse `addr/len` or a bare address (a host prefix).
    pub fn parse(s: &str) -> Option<Self> {
        match s.split_once('/') {
            Some((a, l)) => IpPrefix::new(a.parse().ok()?, l.parse().ok()?),
            None => {
                let a: IpAddr = s.parse().ok()?;
                let len = ip_bits(&a) as u8;
                IpPrefix::new(a, len)
            }
        }
    }

    /// 4 or 6.
    pub fn version(&self) -> u8 {
        if self.addr.is_ipv4() { 4 } else { 6 }
    }

    /// The first address, as an integer.
    pub fn first(&self) -> u128 {
        ip_to_u128(&self.addr)
    }

    /// The last address, as an integer.
    pub fn last(&self) -> u128 {
        let bits = ip_bits(&self.addr);
        self.first() | !net_mask(self.len, bits) & max_for_bits(bits)
    }
}

impl fmt::Display for IpPrefix {
    /// PostgreSQL's `cidr` text form: `192.0.2.0/24`, `2001:db8::/32`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", InetDisplay(&self.addr), self.len)
    }
}

pub(crate) fn ip_bits(a: &IpAddr) -> u32 {
    if a.is_ipv4() { 32 } else { 128 }
}

pub(crate) fn max_for_bits(bits: u32) -> u128 {
    if bits == 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

pub(crate) fn net_mask(len: u8, bits: u32) -> u128 {
    let len = u32::from(len);
    if len == 0 {
        0
    } else {
        max_for_bits(bits) & !(max_for_bits(bits) >> len)
    }
}

pub(crate) fn ip_to_u128(a: &IpAddr) -> u128 {
    match a {
        IpAddr::V4(v) => u128::from(u32::from(*v)),
        IpAddr::V6(v) => u128::from(*v),
    }
}

pub(crate) fn ip_from_u128(v: u128, family: &IpAddr) -> IpAddr {
    match family {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(v as u32)),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(v)),
    }
}

/// Formats an address the way PostgreSQL prints an `inet` host address.
///
/// IPv4 is dotted quad. IPv6 follows PostgreSQL's `inet_net_ntop_ipv6`:
/// the longest run of two or more zero groups becomes `::` (the first one
/// on a tie), hex is lower case, and an IPv4-compatible (`::a.b.c.d`) or
/// IPv4-mapped (`::ffff:a.b.c.d`) address ends in dotted quad.
#[derive(Debug, Clone, Copy)]
pub struct InetDisplay<'a>(pub &'a IpAddr);

impl fmt::Display for InetDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            IpAddr::V4(v) => write!(f, "{v}"),
            IpAddr::V6(v) => f.write_str(&format_ipv6_pg(v)),
        }
    }
}

fn format_ipv6_pg(v: &Ipv6Addr) -> String {
    let words = v.segments();
    // Longest run of zero words.
    let (mut best_base, mut best_len) = (None::<usize>, 0usize);
    let (mut cur_base, mut cur_len) = (None::<usize>, 0usize);
    for (i, w) in words.iter().enumerate() {
        if *w == 0 {
            if cur_base.is_none() {
                cur_base = Some(i);
                cur_len = 1;
            } else {
                cur_len += 1;
            }
        } else if let Some(b) = cur_base {
            if best_base.is_none() || cur_len > best_len {
                best_base = Some(b);
                best_len = cur_len;
            }
            cur_base = None;
        }
    }
    if let Some(b) = cur_base
        && (best_base.is_none() || cur_len > best_len)
    {
        best_base = Some(b);
        best_len = cur_len;
    }
    if best_len < 2 {
        best_base = None;
    }
    let mut out = String::with_capacity(41);
    let mut i = 0;
    while i < 8 {
        if let Some(b) = best_base
            && i >= b
            && i < b + best_len
        {
            if i == b {
                out.push(':');
            }
            i += 1;
            continue;
        }
        if i != 0 {
            out.push(':');
        }
        // Encapsulated IPv4 address?
        if i == 6
            && best_base == Some(0)
            && (best_len == 6 || (best_len == 5 && words[5] == 0xffff))
        {
            let o = v.octets();
            out.push_str(&format!("{}.{}.{}.{}", o[12], o[13], o[14], o[15]));
            break;
        }
        out.push_str(&format!("{:x}", words[i]));
        i += 1;
    }
    if let Some(b) = best_base
        && b + best_len == 8
    {
        out.push(':');
    }
    out
}

/// A JSON or JSONB column value, kept as compact JSON text.
///
/// [`Json::canonical`] puts object keys in the order PostgreSQL's `jsonb`
/// stores them (shorter keys first, then bytewise), so the same document
/// is the same bytes whether it came from v4's database or from irrd-ng.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Json(pub String);

impl Json {
    /// Canonicalise JSON text: `jsonb` key order, compact, no duplicate keys
    /// (the last one wins, as in `jsonb`).
    pub fn canonical(text: &str) -> Result<Json, serde_json::Error> {
        let v: serde_json::Value = serde_json::from_str(text)?;
        Ok(Json::from_value(&v))
    }

    /// Canonical text for a parsed value.
    pub fn from_value(v: &serde_json::Value) -> Json {
        let mut out = String::new();
        write_jsonb_canonical(v, &mut out);
        Json(out)
    }

    /// The JSON text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parse the text.
    pub fn value(&self) -> serde_json::Value {
        serde_json::from_str(&self.0).unwrap_or(serde_json::Value::Null)
    }
}

/// `jsonb` key order: by length, then bytewise.
pub(crate) fn jsonb_key_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.len()
        .cmp(&b.len())
        .then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

pub(crate) fn write_jsonb_canonical(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| jsonb_key_cmp(a, b));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String((*k).clone()).to_string());
                out.push(':');
                write_jsonb_canonical(&map[*k], out);
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jsonb_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

macro_rules! pg_enum {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $variant:ident = $label:literal / $value:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub enum $name {
            $($(#[$vm])* $variant),+
        }

        impl $name {
            /// Every variant, in v4's declaration order.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// The PostgreSQL enum label v4 stores (the Python member name).
            pub fn pg_label(self) -> &'static str {
                match self { $($name::$variant => $label),+ }
            }

            /// The Python enum value, as v4 shows it in some outputs.
            pub fn py_value(self) -> &'static str {
                match self { $($name::$variant => $value),+ }
            }

            /// From the PostgreSQL enum label.
            pub fn from_pg_label(s: &str) -> Option<Self> {
                match s { $($label => Some($name::$variant),)+ _ => None }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.pg_label())
            }
        }
    };
}

pg_enum!(
    /// `RPKIStatus` (`rpkistatus`).
    RpkiStatus {
        /// `valid`
        Valid = "valid" / "VALID",
        /// `invalid`
        Invalid = "invalid" / "INVALID",
        /// `not_found`, the default.
        NotFound = "not_found" / "NOT_FOUND",
    }
);

pg_enum!(
    /// `ScopeFilterStatus` (`scopefilterstatus`).
    ScopeFilterStatus {
        /// `in_scope`, the default.
        InScope = "in_scope" / "IN_SCOPE",
        /// `out_scope_as`
        OutScopeAs = "out_scope_as" / "OUT_SCOPE_AS",
        /// `out_scope_prefix`
        OutScopePrefix = "out_scope_prefix" / "OUT_SCOPE_PREFIX",
    }
);

pg_enum!(
    /// `RoutePreferenceStatus` (`routepreferencestatus`).
    RoutePreferenceStatus {
        /// `visible`, the default.
        Visible = "visible" / "VISIBLE",
        /// `suppressed`
        Suppressed = "suppressed" / "SUPPRESSED",
    }
);

pg_enum!(
    /// `DatabaseOperation` (`databaseoperation`).
    DatabaseOperation {
        /// `add_or_update` (NRTM `ADD`).
        AddOrUpdate = "add_or_update" / "ADD",
        /// `delete` (NRTM `DEL`).
        Delete = "delete" / "DEL",
    }
);

pg_enum!(
    /// `JournalEntryOrigin` (`journalentryorigin`).
    JournalEntryOrigin {
        /// Legacy entries of unknown origin.
        Unknown = "unknown" / "UNKNOWN",
        /// Received from a mirror by NRTM or file import.
        Mirror = "mirror" / "MIRROR",
        /// Generated from synthesized NRTM.
        SyntheticNrtm = "synthetic_nrtm" / "SYNTHETIC_NRTM",
        /// Generated from the RPKI pseudo-IRR.
        PseudoIrr = "pseudo_irr" / "PSEUDO_IRR",
        /// A user-submitted change in an authoritative database.
        AuthChange = "auth_change" / "AUTH_CHANGE",
        /// An RPKI status change in an authoritative database.
        RpkiStatus = "rpki_status" / "RPKI_STATUS",
        /// A scope filter status change.
        ScopeFilter = "scope_filter" / "SCOPE_FILTER",
        /// Suspension or reactivation.
        Suspension = "suspension" / "SUSPENSION",
        /// A route preference status change.
        RoutePreference = "route_preference" / "ROUTE_PREFERENCE",
    }
);

pg_enum!(
    /// `UpdateRequestType` (`updaterequesttype`), used by `change_log`.
    UpdateRequestType {
        /// `CREATE`
        Create = "CREATE" / "create",
        /// `MODIFY`
        Modify = "MODIFY" / "modify",
        /// `DELETE`
        Delete = "DELETE" / "delete",
    }
);

/// `object_is_visible()`: not suppressed by RPKI, scope filter or route
/// preference.
pub fn object_is_visible(
    rpki: RpkiStatus,
    scopefilter: ScopeFilterStatus,
    route_preference: RoutePreferenceStatus,
) -> bool {
    matches!(rpki, RpkiStatus::Valid | RpkiStatus::NotFound)
        && scopefilter == ScopeFilterStatus::InScope
        && route_preference == RoutePreferenceStatus::Visible
}

/// A row of `rpsl_objects`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpslObjectRow {
    /// `pk`: the row UUID.
    pub pk: Uuid,
    /// `rpsl_pk`: the RPSL primary key, upper case.
    pub rpsl_pk: String,
    /// `source`
    pub source: String,
    /// `object_class`
    pub object_class: String,
    /// `parsed_data` (JSONB).
    pub parsed_data: Json,
    /// `object_text`, verbatim.
    pub object_text: String,
    /// `ip_version`
    pub ip_version: Option<u8>,
    /// `ip_first` (INET, a host address).
    pub ip_first: Option<IpAddr>,
    /// `ip_last` (INET, a host address).
    pub ip_last: Option<IpAddr>,
    /// `prefix_length`
    pub prefix_length: Option<u32>,
    /// `prefix` (CIDR).
    pub prefix: Option<IpPrefix>,
    /// `asn_first` (BIGINT).
    pub asn_first: Option<u32>,
    /// `asn_last` (BIGINT).
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

impl RpslObjectRow {
    /// `ip_size`: `ip_last - ip_first + 1`, as v4 computes it on every
    /// upsert, in decimal. `None` without both addresses.
    pub fn ip_size(&self) -> Option<String> {
        ip_size(self.ip_first.as_ref(), self.ip_last.as_ref())
    }

    /// Visible under v4's default suppression.
    pub fn is_visible(&self) -> bool {
        object_is_visible(
            self.rpki_status,
            self.scopefilter_status,
            self.route_preference_status,
        )
    }
}

/// `ip_size` for an address range, in decimal (it can be 2^128).
pub fn ip_size(first: Option<&IpAddr>, last: Option<&IpAddr>) -> Option<String> {
    let (f, l) = (ip_to_u128(first?), ip_to_u128(last?));
    let diff = l.wrapping_sub(f);
    Some(match diff.checked_add(1) {
        Some(v) => v.to_string(),
        None => "340282366920938463463374607431768211456".to_owned(),
    })
}

/// A row of `rpsl_database_journal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// `pk`
    pub pk: Uuid,
    /// `serial_global`, from the journal-wide sequence.
    pub serial_global: i64,
    /// `rpsl_pk`
    pub rpsl_pk: String,
    /// `source`
    pub source: String,
    /// `origin`
    pub origin: JournalEntryOrigin,
    /// `serial_nrtm` (INTEGER), unique per source.
    pub serial_nrtm: i64,
    /// `operation`
    pub operation: DatabaseOperation,
    /// `object_class`
    pub object_class: String,
    /// `object_text`
    pub object_text: String,
    /// `timestamp`
    pub timestamp: Timestamp,
}

/// A row of `database_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseStatus {
    /// `pk`
    pub pk: Uuid,
    /// `source`
    pub source: String,
    /// `serial_oldest_seen`
    pub serial_oldest_seen: Option<i64>,
    /// `serial_newest_seen`
    pub serial_newest_seen: Option<i64>,
    /// `serial_oldest_journal`
    pub serial_oldest_journal: Option<i64>,
    /// `serial_newest_journal`
    pub serial_newest_journal: Option<i64>,
    /// `serial_last_export`
    pub serial_last_export: Option<i64>,
    /// `serial_newest_mirror`
    pub serial_newest_mirror: Option<i64>,
    /// `nrtm4_client_session_id`
    pub nrtm4_client_session_id: Option<Uuid>,
    /// `nrtm4_client_version`
    pub nrtm4_client_version: Option<i64>,
    /// `nrtm4_client_current_key`
    pub nrtm4_client_current_key: Option<String>,
    /// `nrtm4_client_next_key`
    pub nrtm4_client_next_key: Option<String>,
    /// `nrtm4_client_previous_file_hashes` (JSONB).
    pub nrtm4_client_previous_file_hashes: Option<Json>,
    /// `nrtm4_server_session_id`
    pub nrtm4_server_session_id: Option<Uuid>,
    /// `nrtm4_server_version`
    pub nrtm4_server_version: Option<i64>,
    /// `nrtm4_server_last_update_notification_file_update`
    pub nrtm4_server_last_update_notification_file_update: Option<Timestamp>,
    /// `nrtm4_server_last_snapshot_version`
    pub nrtm4_server_last_snapshot_version: Option<i64>,
    /// `nrtm4_server_last_snapshot_global_serial`
    pub nrtm4_server_last_snapshot_global_serial: Option<i64>,
    /// `nrtm4_server_last_snapshot_timestamp`
    pub nrtm4_server_last_snapshot_timestamp: Option<Timestamp>,
    /// `nrtm4_server_last_snapshot_filename`
    pub nrtm4_server_last_snapshot_filename: Option<String>,
    /// `nrtm4_server_last_snapshot_hash`
    pub nrtm4_server_last_snapshot_hash: Option<String>,
    /// `nrtm4_server_previous_deltas` (JSONB).
    pub nrtm4_server_previous_deltas: Option<Json>,
    /// `force_reload`
    pub force_reload: bool,
    /// `synchronised_serials`
    pub synchronised_serials: bool,
    /// `last_error`
    pub last_error: Option<String>,
    /// `last_error_timestamp`
    pub last_error_timestamp: Option<Timestamp>,
    /// `rpsl_data_updated`
    pub rpsl_data_updated: Timestamp,
    /// `created`
    pub created: Timestamp,
    /// `updated`
    pub updated: Timestamp,
}

impl DatabaseStatus {
    /// A fresh row as v4's `finalise_transaction` inserts it: every serial
    /// and NRTMv4 column NULL.
    pub fn new(source: &str, now: Timestamp) -> Self {
        DatabaseStatus {
            pk: Uuid::new_v4(),
            source: source.to_owned(),
            serial_oldest_seen: None,
            serial_newest_seen: None,
            serial_oldest_journal: None,
            serial_newest_journal: None,
            serial_last_export: None,
            serial_newest_mirror: None,
            nrtm4_client_session_id: None,
            nrtm4_client_version: None,
            nrtm4_client_current_key: None,
            nrtm4_client_next_key: None,
            nrtm4_client_previous_file_hashes: None,
            nrtm4_server_session_id: None,
            nrtm4_server_version: None,
            nrtm4_server_last_update_notification_file_update: None,
            nrtm4_server_last_snapshot_version: None,
            nrtm4_server_last_snapshot_global_serial: None,
            nrtm4_server_last_snapshot_timestamp: None,
            nrtm4_server_last_snapshot_filename: None,
            nrtm4_server_last_snapshot_hash: None,
            nrtm4_server_previous_deltas: None,
            force_reload: false,
            synchronised_serials: true,
            last_error: None,
            last_error_timestamp: None,
            rpsl_data_updated: now,
            created: now,
            updated: now,
        }
    }
}

/// `NRTM4ClientDatabaseStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Nrtm4ClientStatus {
    /// `session_id`
    pub session_id: Option<Uuid>,
    /// `version`
    pub version: Option<i64>,
    /// `current_key`
    pub current_key: Option<String>,
    /// `next_key`
    pub next_key: Option<String>,
    /// `previous_file_hashes`
    pub previous_file_hashes: Option<Json>,
}

/// `NRTM4ServerDatabaseStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Nrtm4ServerStatus {
    /// `session_id`
    pub session_id: Option<Uuid>,
    /// `version`
    pub version: Option<i64>,
    /// `last_update_notification_file_update`
    pub last_update_notification_file_update: Option<Timestamp>,
    /// `last_snapshot_version`
    pub last_snapshot_version: Option<i64>,
    /// `last_snapshot_global_serial`
    pub last_snapshot_global_serial: Option<i64>,
    /// `last_snapshot_filename`
    pub last_snapshot_filename: Option<String>,
    /// `last_snapshot_timestamp`
    pub last_snapshot_timestamp: Option<Timestamp>,
    /// `last_snapshot_hash`
    pub last_snapshot_hash: Option<String>,
    /// `previous_deltas` (a JSON list).
    pub previous_deltas: Option<Json>,
}

/// A row of `roa_object`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoaRow {
    /// `pk`
    pub pk: Uuid,
    /// `prefix` (CIDR).
    pub prefix: IpPrefix,
    /// `asn` (BIGINT).
    pub asn: i64,
    /// `max_length`
    pub max_length: i64,
    /// `trust_anchor`
    pub trust_anchor: Option<String>,
    /// `ip_version`
    pub ip_version: u8,
    /// `created`
    pub created: Timestamp,
}

/// A row of `rpsl_objects_suspended`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuspendedObjectRow {
    /// `pk`
    pub pk: Uuid,
    /// `rpsl_pk`
    pub rpsl_pk: String,
    /// `source`
    pub source: String,
    /// `object_class`
    pub object_class: String,
    /// `object_text`
    pub object_text: String,
    /// `mntners` (TEXT[]).
    pub mntners: Vec<String>,
    /// `timestamp`
    pub timestamp: Timestamp,
    /// `original_created`
    pub original_created: Timestamp,
    /// `original_updated`
    pub original_updated: Timestamp,
}

/// A row of `protected_rpsl_name`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedNameRow {
    /// `pk`
    pub pk: Uuid,
    /// `rpsl_pk`
    pub rpsl_pk: String,
    /// `source`
    pub source: String,
    /// `object_class`
    pub object_class: String,
    /// `protected_name`
    pub protected_name: String,
    /// `created`
    pub created: Timestamp,
}

/// A row of `setting`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingRow {
    /// `name`
    pub name: String,
    /// `value`
    pub value: Option<String>,
    /// `created`
    pub created: Timestamp,
}

/// A row of `auth_user`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthUserRow {
    /// `pk`
    pub pk: Uuid,
    /// `email`
    pub email: String,
    /// `name`
    pub name: String,
    /// `password` (a hash).
    pub password: String,
    /// `totp_secret`
    pub totp_secret: Option<String>,
    /// `totp_last_used`
    pub totp_last_used: Option<String>,
    /// `active`
    pub active: bool,
    /// `override`
    pub override_: bool,
    /// `created`
    pub created: Timestamp,
    /// `updated`
    pub updated: Timestamp,
}

/// A row of `auth_permission`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPermissionRow {
    /// `pk`
    pub pk: Uuid,
    /// `user_id`
    pub user_id: Option<Uuid>,
    /// `mntner_id`
    pub mntner_id: Option<Uuid>,
    /// `user_management`
    pub user_management: bool,
    /// `created`
    pub created: Timestamp,
    /// `updated`
    pub updated: Timestamp,
}

/// A row of `auth_mntner`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthMntnerRow {
    /// `pk`
    pub pk: Uuid,
    /// `rpsl_mntner_pk`
    pub rpsl_mntner_pk: String,
    /// `rpsl_mntner_obj_id`: the `rpsl_objects.pk` of the mntner.
    pub rpsl_mntner_obj_id: Uuid,
    /// `rpsl_mntner_source`
    pub rpsl_mntner_source: String,
    /// `migration_token`
    pub migration_token: Option<String>,
    /// `created`
    pub created: Timestamp,
    /// `updated`
    pub updated: Timestamp,
}

/// A row of `auth_api_token`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthApiTokenRow {
    /// `pk`
    pub pk: Uuid,
    /// `token`
    pub token: Option<Uuid>,
    /// `name`
    pub name: String,
    /// `creator_id`
    pub creator_id: Option<Uuid>,
    /// `mntner_id`
    pub mntner_id: Option<Uuid>,
    /// `ip_restriction`: comma separated prefixes.
    pub ip_restriction: Option<String>,
    /// `enabled_webapi`
    pub enabled_webapi: bool,
    /// `enabled_email`
    pub enabled_email: bool,
    /// `created`
    pub created: Timestamp,
    /// `updated`
    pub updated: Timestamp,
}

/// A row of `auth_webauthn`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthWebAuthnRow {
    /// `pk`
    pub pk: Uuid,
    /// `user_id`
    pub user_id: Option<Uuid>,
    /// `name`
    pub name: String,
    /// `credential_id` (BYTEA).
    pub credential_id: Vec<u8>,
    /// `credential_public_key` (BYTEA).
    pub credential_public_key: Vec<u8>,
    /// `credential_sign_count`
    pub credential_sign_count: i64,
    /// `created`
    pub created: Timestamp,
    /// `last_used`
    pub last_used: Timestamp,
}

/// A row of `change_log`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeLogRow {
    /// `pk`
    pub pk: Uuid,
    /// `auth_by_user_id`
    pub auth_by_user_id: Option<Uuid>,
    /// `auth_by_user_email`
    pub auth_by_user_email: Option<String>,
    /// `auth_by_api_key_id`
    pub auth_by_api_key_id: Option<Uuid>,
    /// `auth_by_api_key_id_fixed`
    pub auth_by_api_key_id_fixed: Option<Uuid>,
    /// `auth_through_mntner_id`
    pub auth_through_mntner_id: Option<Uuid>,
    /// `auth_through_rpsl_mntner_pk`
    pub auth_through_rpsl_mntner_pk: Option<String>,
    /// `auth_by_rpsl_mntner_password`
    pub auth_by_rpsl_mntner_password: bool,
    /// `auth_by_rpsl_mntner_pgp_key`
    pub auth_by_rpsl_mntner_pgp_key: bool,
    /// `auth_by_override` (nullable).
    pub auth_by_override: Option<bool>,
    /// `from_email`
    pub from_email: Option<String>,
    /// `from_ip` (INET), in PostgreSQL's text form.
    pub from_ip: Option<String>,
    /// `auth_change_descr`
    pub auth_change_descr: Option<String>,
    /// `auth_affected_user_id`
    pub auth_affected_user_id: Option<Uuid>,
    /// `auth_affected_mntner_id`
    pub auth_affected_mntner_id: Option<Uuid>,
    /// `rpsl_target_request_type`
    pub rpsl_target_request_type: Option<UpdateRequestType>,
    /// `rpsl_target_pk`
    pub rpsl_target_pk: Option<String>,
    /// `rpsl_target_source`
    pub rpsl_target_source: Option<String>,
    /// `rpsl_target_object_class`
    pub rpsl_target_object_class: Option<String>,
    /// `rpsl_target_object_text_old`
    pub rpsl_target_object_text_old: Option<String>,
    /// `rpsl_target_object_text_new`
    pub rpsl_target_object_text_new: Option<String>,
    /// `timestamp`
    pub timestamp: Timestamp,
}

/// An RPSL object to upsert through the v4 `DatabaseHandler` path
/// ([`crate::WriteTx::upsert_rpsl_object`]): the fields v4 reads from an
/// `RPSLObject`. The row UUID, `created` and `updated` are assigned by the
/// store; `object_text` must already be rendered as v4's
/// `render_rpsl_text(last_modified=...)` would. The secondary indexes are
/// derived from `parsed_data`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewRpslObject {
    /// `pk()`
    pub rpsl_pk: String,
    /// `parsed_data["source"]`
    pub source: String,
    /// `rpsl_object_class`
    pub object_class: String,
    /// `parsed_data`
    pub parsed_data: Json,
    /// `render_rpsl_text(last_modified=...)`
    pub object_text: String,
    /// `ip_first`
    pub ip_first: Option<IpAddr>,
    /// `ip_last`
    pub ip_last: Option<IpAddr>,
    /// `prefix`
    pub prefix: Option<IpPrefix>,
    /// `prefix_length`
    pub prefix_length: Option<u32>,
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
}

/// An object whose RPKI, scope filter or route preference status changed,
/// as v4's validators hand it to `update_*_status`: the row and the status
/// it had before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusChange<S> {
    /// `pk`: the row UUID.
    pub pk: Uuid,
    /// `rpsl_pk`, used by `update_scopefilter_status`, which v4 matches on
    /// the RPSL primary key rather than the row.
    pub rpsl_pk: String,
    /// The status before the change (`old_status`).
    pub old_status: S,
    /// The new status.
    pub new_status: S,
}
