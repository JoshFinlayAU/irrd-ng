//! Secondary index maintenance and lookups.
//!
//! Every index entry is derived from the stored record alone, so removing
//! an object recomputes exactly the keys that adding it wrote.
//!
//! | table | key | value | answers |
//! |---|---|---|---|
//! | `objects_key` | source, class, rpsl_pk | id | the unique key; key lookups; per source/class scans |
//! | `objects_uuid` | row UUID | id | `pk` filters |
//! | `idx_rpsl_pk` | rpsl_pk, id | | `rpsl_pk IN (...)` across classes and sources |
//! | `idx_lookup` | attribute code, value, id | | `parsed_data->attr ? value` (`-i`, `!o`, member-of, ...) |
//! | `idx_lookup` | attribute code, `0xFF`, id | | `parsed_data ? attr`, for `member-of` and `mbrs-by-ref` only |
//! | `set_members` | rpsl_pk, source, class | members, mbrs-by-ref | set expansion (`!i`, `!a`) |
//! | `idx_ip{4,6}_range` | ip_first, ip_last, id | | exact and more-specific (`!r`, `-x`, `-M`) |
//! | `idx_ip{4,6}_cover` | cover length, cover network, id | ip_first, ip_last | less-specific (`-l`, `-L`, `!r..,l/L`) |
//! | `idx_asn_range` | asn_first, asn_last, id | | exact ASN, `asn_first IN (...)` |
//! | `idx_asn_cover` | cover length, cover, id | asn_first, asn_last | `asn_first <= x <= asn_last` |
//! | `idx_route_origin` | source, origin, version, network, length, id | statuses | `!g`, `!6`, `!a` |
//!
//! The cover of an address or AS range is the smallest prefix containing
//! it. A range contains `[a, b]` only if its cover does, and every cover of
//! `[a, b]` is `a` masked to a length no longer than the common prefix of
//! `a` and `b`, so a less-specific search is at most 33 (129) prefix scans.

use std::collections::BTreeSet;
use std::net::IpAddr;

use heed::{RoTxn, RwTxn};

use crate::env::Tables;
use crate::error::{Result, StoreError};
use crate::keys::{
    common_prefix_len, id_bytes, id_from_tail, mask, push_index_str, push_str, push_uint, read_uint,
};
use crate::model::{RoutePreferenceStatus, RpkiStatus, ScopeFilterStatus, ip_to_u128};
use crate::records::{RpslObjectRef, SetMembers, decode, encode};

/// v4's `lookup_field_names()`, checked against `expected_lookup_field_names`
/// in `irrd/storage/models.py`.
pub const LOOKUP_FIELD_NAMES: &[&str] = &[
    "admin-c",
    "tech-c",
    "zone-c",
    "member-of",
    "mnt-by",
    "role",
    "members",
    "person",
    "mp-members",
    "origin",
    "mbrs-by-ref",
];

const PRESENCE: u8 = 0xFF;

/// Attributes whose presence (`parsed_data ? attr`) is indexed. v4 only
/// asks that of `member-of` (the preload's `mbrs-by-ref` resolution);
/// `mbrs-by-ref` is kept for the same reason. Presence of any other
/// attribute is answered by a scan.
const PRESENCE_INDEXED: &[&str] = &["member-of", "mbrs-by-ref"];

/// The one-byte code of a look-up attribute in `idx_lookup` keys: its
/// position in [`LOOKUP_FIELD_NAMES`].
fn lookup_code(attr: &str) -> Option<u8> {
    LOOKUP_FIELD_NAMES
        .iter()
        .position(|a| *a == attr)
        .map(|i| i as u8)
}

fn status_bytes(r: &RpslObjectRef<'_>) -> [u8; 3] {
    [
        match r.rpki_status {
            RpkiStatus::Valid => 0,
            RpkiStatus::Invalid => 1,
            RpkiStatus::NotFound => 2,
        },
        match r.scopefilter_status {
            ScopeFilterStatus::InScope => 0,
            ScopeFilterStatus::OutScopeAs => 1,
            ScopeFilterStatus::OutScopePrefix => 2,
        },
        match r.route_preference_status {
            RoutePreferenceStatus::Visible => 0,
            RoutePreferenceStatus::Suppressed => 1,
        },
    ]
}

/// The statuses stored in a route origin index value.
pub fn statuses_from_bytes(
    b: &[u8],
) -> Option<(RpkiStatus, ScopeFilterStatus, RoutePreferenceStatus)> {
    let rpki = match b.first()? {
        0 => RpkiStatus::Valid,
        1 => RpkiStatus::Invalid,
        _ => RpkiStatus::NotFound,
    };
    let sf = match b.get(1)? {
        0 => ScopeFilterStatus::InScope,
        1 => ScopeFilterStatus::OutScopeAs,
        _ => ScopeFilterStatus::OutScopePrefix,
    };
    let rp = match b.get(2)? {
        0 => RoutePreferenceStatus::Visible,
        _ => RoutePreferenceStatus::Suppressed,
    };
    Some((rpki, sf, rp))
}

pub(crate) fn object_key(source: &str, class: &str, rpsl_pk: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(source.len() + class.len() + rpsl_pk.len() + 6);
    push_str(&mut k, source.as_bytes());
    push_str(&mut k, class.as_bytes());
    push_str(&mut k, rpsl_pk.as_bytes());
    k
}

pub(crate) fn source_prefix(source: &str) -> Vec<u8> {
    let mut k = Vec::new();
    push_str(&mut k, source.as_bytes());
    k
}

fn lookup_values(parsed: &serde_json::Value) -> Vec<(&'static str, Vec<&str>)> {
    let mut out = Vec::new();
    let Some(map) = parsed.as_object() else {
        return out;
    };
    for name in LOOKUP_FIELD_NAMES {
        if let Some(v) = map.get(*name) {
            let values = match v {
                serde_json::Value::String(s) => vec![s.as_str()],
                serde_json::Value::Array(items) => {
                    items.iter().filter_map(|i| i.as_str()).collect()
                }
                _ => Vec::new(),
            };
            out.push((*name, values));
        }
    }
    out
}

fn json_str_list<'a>(parsed: &'a serde_json::Value, name: &str) -> Vec<&'a str> {
    match parsed.get(name) {
        Some(serde_json::Value::String(s)) => vec![s.as_str()],
        Some(serde_json::Value::Array(items)) => items.iter().filter_map(|i| i.as_str()).collect(),
        _ => Vec::new(),
    }
}

fn family(a: &IpAddr) -> (u32, usize) {
    if a.is_ipv4() { (32, 4) } else { (128, 16) }
}

/// The index entries of one object, as (table selector, key, value).
fn entries(r: &RpslObjectRef<'_>, id: u64) -> Vec<(Idx, Vec<u8>, Vec<u8>)> {
    let idb = id_bytes(id);
    let mut out = Vec::new();

    let mut k = Vec::new();
    push_index_str(&mut k, r.rpsl_pk);
    k.extend_from_slice(&idb);
    out.push((Idx::RpslPk, k, Vec::new()));

    let parsed: serde_json::Value =
        serde_json::from_str(r.parsed_data).unwrap_or(serde_json::Value::Null);
    let mut seen = BTreeSet::new();
    for (attr, values) in lookup_values(&parsed) {
        let Some(code) = lookup_code(attr) else {
            continue;
        };
        if PRESENCE_INDEXED.contains(&attr) {
            out.push((
                Idx::Lookup,
                vec![code, PRESENCE].into_iter().chain(idb).collect(),
                Vec::new(),
            ));
        }
        for v in values {
            let mut k = vec![code];
            push_index_str(&mut k, v);
            k.extend_from_slice(&idb);
            if seen.insert(k.clone()) {
                out.push((Idx::Lookup, k, Vec::new()));
            }
        }
    }

    if r.object_class == "as-set" || r.object_class == "route-set" {
        let mut members = json_str_list(&parsed, "members");
        members.extend(json_str_list(&parsed, "mp-members"));
        let sm = SetMembers {
            members,
            mbrs_by_ref: json_str_list(&parsed, "mbrs-by-ref"),
        };
        let mut k = Vec::new();
        push_str(&mut k, r.rpsl_pk.as_bytes());
        push_str(&mut k, r.source.as_bytes());
        push_str(&mut k, r.object_class.as_bytes());
        // A set member list cannot fail to encode.
        let v = encode(&sm).unwrap_or_default();
        out.push((Idx::SetMembers, k, v));
    }

    // An IPv6 object within `::/96` has an IPv4 `ip_last`: v4 stores
    // `str(IP.broadcast())`, and IPy re-guesses the version from the
    // integer. It is indexed in the IPv6 tables by the integer value; the
    // query engine applies v4's family-aware comparisons on top.
    if let (Some(first), Some(last)) = (r.ip_first, r.ip_last)
        && (first.is_ipv4() == last.is_ipv4() || first.is_ipv6())
    {
        let (bits, width) = family(&first);
        let (f, l) = (ip_to_u128(&first), ip_to_u128(&last));
        let (range, cover) = if bits == 32 {
            (Idx::Ip4Range, Idx::Ip4Cover)
        } else {
            (Idx::Ip6Range, Idx::Ip6Cover)
        };
        out.push((range, range_key(f, l, width, id), Vec::new()));
        let (ck, cv) = cover_entry(f, l, bits, width, id);
        out.push((cover, ck, cv));
    }

    if let (Some(f), Some(l)) = (r.asn_first, r.asn_last) {
        out.push((
            Idx::AsnRange,
            range_key(u128::from(f), u128::from(l), 4, id),
            Vec::new(),
        ));
        let (ck, cv) = cover_entry(u128::from(f), u128::from(l), 32, 4, id);
        out.push((Idx::AsnCover, ck, cv));
    }

    if (r.object_class == "route" || r.object_class == "route6")
        && let (Some(first), Some(len), Some(asn)) = (r.ip_first, r.prefix_length, r.asn_first)
    {
        let (_, width) = family(&first);
        let mut k = Vec::new();
        push_str(&mut k, r.source.as_bytes());
        k.extend_from_slice(&asn.to_be_bytes());
        k.push(if first.is_ipv4() { 4 } else { 6 });
        push_uint(&mut k, ip_to_u128(&first), width);
        k.push(len.min(255) as u8);
        k.extend_from_slice(&idb);
        out.push((Idx::RouteOrigin, k, status_bytes(r).to_vec()));
    }
    out
}

fn range_key(first: u128, last: u128, width: usize, id: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(width * 2 + 8);
    push_uint(&mut k, first, width);
    push_uint(&mut k, last, width);
    k.extend_from_slice(&id_bytes(id));
    k
}

fn cover_entry(first: u128, last: u128, bits: u32, width: usize, id: u64) -> (Vec<u8>, Vec<u8>) {
    let len = common_prefix_len(first, last, bits);
    let mut k = Vec::with_capacity(width + 9);
    k.push(len);
    push_uint(&mut k, mask(first, len, bits), width);
    k.extend_from_slice(&id_bytes(id));
    let mut v = Vec::with_capacity(width * 2);
    push_uint(&mut v, first, width);
    push_uint(&mut v, last, width);
    (k, v)
}

#[derive(Debug, Clone, Copy)]
enum Idx {
    RpslPk,
    Lookup,
    SetMembers,
    Ip4Range,
    Ip4Cover,
    Ip6Range,
    Ip6Cover,
    AsnRange,
    AsnCover,
    RouteOrigin,
}

fn table(t: &Tables, i: Idx) -> crate::env::Table {
    match i {
        Idx::RpslPk => t.idx_rpsl_pk,
        Idx::Lookup => t.idx_lookup,
        Idx::SetMembers => t.set_members,
        Idx::Ip4Range => t.ip4_range,
        Idx::Ip4Cover => t.ip4_cover,
        Idx::Ip6Range => t.ip6_range,
        Idx::Ip6Cover => t.ip6_cover,
        Idx::AsnRange => t.asn_range,
        Idx::AsnCover => t.asn_cover,
        Idx::RouteOrigin => t.route_origin,
    }
}

/// Write every index entry for an object.
pub(crate) fn add(wtxn: &mut RwTxn<'_>, t: &Tables, r: &RpslObjectRef<'_>, id: u64) -> Result<()> {
    for (i, k, v) in entries(r, id) {
        table(t, i).put(wtxn, &k, &v)?;
    }
    Ok(())
}

/// Add the address range entries of IPv6 objects with an IPv4 `ip_last`,
/// which schema versions before 3 did not index (migration 2 to 3).
pub(crate) fn index_mixed_family_ranges(wtxn: &mut RwTxn<'_>, t: &Tables) -> Result<()> {
    let mut add: Vec<(Idx, Vec<u8>, Vec<u8>)> = Vec::new();
    for item in t.objects.iter(wtxn)? {
        let (k, v) = item?;
        let id = u64::from_be_bytes(k.try_into().map_err(|_| StoreError::Corrupt("object id"))?);
        let r: RpslObjectRef<'_> = decode(v)?;
        if let (Some(f), Some(l)) = (r.ip_first, r.ip_last)
            && f.is_ipv6()
            && l.is_ipv4()
        {
            add.extend(
                entries(&r, id)
                    .into_iter()
                    .filter(|(i, _, _)| matches!(i, Idx::Ip6Range | Idx::Ip6Cover)),
            );
        }
    }
    for (i, k, v) in add {
        table(t, i).put(wtxn, &k, &v)?;
    }
    Ok(())
}

/// Rebuild `idx_lookup` from the objects table (schema migration 1 to 2).
pub(crate) fn rebuild_lookup(wtxn: &mut RwTxn<'_>, t: &Tables) -> Result<()> {
    t.idx_lookup.clear(wtxn)?;
    let mut entries_out: Vec<Vec<u8>> = Vec::new();
    {
        for item in t.objects.iter(wtxn)? {
            let (k, v) = item?;
            let id =
                u64::from_be_bytes(k.try_into().map_err(|_| StoreError::Corrupt("object id"))?);
            let r: RpslObjectRef<'_> = decode(v)?;
            for (i, key, _) in entries(&r, id) {
                if matches!(i, Idx::Lookup) {
                    entries_out.push(key);
                }
            }
        }
    }
    entries_out.sort_unstable();
    for k in entries_out {
        t.idx_lookup.put(wtxn, &k, &[])?;
    }
    Ok(())
}

/// Remove every index entry for an object.
pub(crate) fn remove(
    wtxn: &mut RwTxn<'_>,
    t: &Tables,
    r: &RpslObjectRef<'_>,
    id: u64,
) -> Result<()> {
    for (i, k, v) in entries(r, id) {
        match i {
            // Set members are keyed without the id: only remove the entry
            // if it is this object's (it always is, the key is unique).
            Idx::SetMembers => {
                let _ = v;
                table(t, i).delete(wtxn, &k)?;
            }
            _ => {
                table(t, i).delete(wtxn, &k)?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Lookups. All return internal object ids; callers load the records.
// ---------------------------------------------------------------------

/// Ids of objects whose `rpsl_pk` is exactly `rpsl_pk`.
pub(crate) fn ids_by_rpsl_pk(t: &Tables, txn: &RoTxn<'_>, rpsl_pk: &str) -> Result<Vec<u64>> {
    let mut p = Vec::new();
    let cut = push_index_str(&mut p, rpsl_pk);
    let mut out = Vec::new();
    for item in t.idx_rpsl_pk.prefix_iter(txn, &p)? {
        let (k, _) = item?;
        if k.len() != p.len() + 8 {
            continue;
        }
        let id = id_from_tail(k).ok_or(StoreError::Corrupt("index key"))?;
        if cut && !crate::query::object_by_id(t, txn, id)?.is_some_and(|o| o.rpsl_pk == rpsl_pk) {
            continue;
        }
        out.push(id);
    }
    Ok(out)
}

/// Ids of objects whose `parsed_data[attr]` contains `value` exactly
/// (`Some`), or which have `attr` at all (`None`).
pub(crate) fn ids_by_lookup(
    t: &Tables,
    txn: &RoTxn<'_>,
    attr: &str,
    value: Option<&str>,
) -> Result<Vec<u64>> {
    let Some(code) = lookup_code(attr) else {
        return Ok(Vec::new());
    };
    if value.is_none() && !PRESENCE_INDEXED.contains(&attr) {
        return ids_with_attribute_scan(t, txn, attr);
    }
    let mut p = vec![code];
    let cut = match value {
        Some(v) => push_index_str(&mut p, v),
        None => {
            p.push(PRESENCE);
            false
        }
    };
    let mut out = Vec::new();
    for item in t.idx_lookup.prefix_iter(txn, &p)? {
        let (k, _) = item?;
        if k.len() != p.len() + 8 {
            continue;
        }
        let id = id_from_tail(k).ok_or(StoreError::Corrupt("index key"))?;
        if cut {
            let Some(o) = crate::query::object_by_id(t, txn, id)? else {
                continue;
            };
            let parsed = o.parsed_data_value();
            if !json_str_list(&parsed, attr).contains(&value.unwrap_or_default()) {
                continue;
            }
        }
        out.push(id);
    }
    Ok(out)
}

/// `parsed_data ? attr` for an attribute whose presence is not indexed.
fn ids_with_attribute_scan(t: &Tables, txn: &RoTxn<'_>, attr: &str) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    for item in t.objects.iter(txn)? {
        let (k, v) = item?;
        let o: RpslObjectRef<'_> = decode(v)?;
        let parsed: serde_json::Value =
            serde_json::from_str(o.parsed_data).unwrap_or(serde_json::Value::Null);
        if parsed.get(attr).is_some() {
            out.push(u64::from_be_bytes(
                k.try_into().map_err(|_| StoreError::Corrupt("object id"))?,
            ));
        }
    }
    Ok(out)
}

/// The forward members of the sets named `rpsl_pk`, per (source, class).
pub(crate) fn set_members<'t>(
    t: &Tables,
    txn: &'t RoTxn<'_>,
    rpsl_pk: &str,
) -> Result<Vec<(String, String, SetMembers<'t>)>> {
    let mut p = Vec::new();
    push_str(&mut p, rpsl_pk.as_bytes());
    let mut out = Vec::new();
    for item in t.set_members.prefix_iter(txn, &p)? {
        let (k, v) = item?;
        let rest = &k[p.len()..];
        let (source, rest) = crate::keys::take_string(rest).ok_or(StoreError::Corrupt("key"))?;
        let (class, _) = crate::keys::take_string(rest).ok_or(StoreError::Corrupt("key"))?;
        out.push((source, class, decode(v)?));
    }
    Ok(out)
}

/// Which address space a range search runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Space {
    /// IPv4 addresses.
    Ipv4,
    /// IPv6 addresses.
    Ipv6,
    /// AS numbers (`asn_first`/`asn_last`).
    Asn,
}

impl Space {
    fn bits_width(self) -> (u32, usize) {
        match self {
            Space::Ipv4 | Space::Asn => (32, 4),
            Space::Ipv6 => (128, 16),
        }
    }

    fn tables(self, t: &Tables) -> (crate::env::Table, crate::env::Table) {
        match self {
            Space::Ipv4 => (t.ip4_range, t.ip4_cover),
            Space::Ipv6 => (t.ip6_range, t.ip6_cover),
            Space::Asn => (t.asn_range, t.asn_cover),
        }
    }

    /// The space of an address.
    pub fn of(a: &IpAddr) -> Space {
        if a.is_ipv4() {
            Space::Ipv4
        } else {
            Space::Ipv6
        }
    }
}

/// Objects whose range starts at or below `first` (any end).
pub(crate) fn ids_range_first_at_most(
    t: &Tables,
    txn: &RoTxn<'_>,
    space: Space,
    first: u128,
) -> Result<Vec<(u64, u128, u128)>> {
    let (_, width) = space.bits_width();
    let (range, _) = space.tables(t);
    let mut hi = Vec::new();
    push_uint(&mut hi, first, width);
    hi.extend_from_slice(&[0xFF; 25]);
    let bounds = (
        std::ops::Bound::Unbounded,
        std::ops::Bound::Included(hi.as_slice()),
    );
    let mut out = Vec::new();
    for item in range.range(txn, &bounds)? {
        let (k, _) = item?;
        let f = read_uint(k, width).ok_or(StoreError::Corrupt("index key"))?;
        let l = read_uint(&k[width..], width).ok_or(StoreError::Corrupt("index key"))?;
        if f <= first {
            out.push((
                id_from_tail(k).ok_or(StoreError::Corrupt("index key"))?,
                f,
                l,
            ));
        }
    }
    Ok(out)
}

/// Objects whose range is exactly `[first, last]`.
pub(crate) fn ids_range_exact(
    t: &Tables,
    txn: &RoTxn<'_>,
    space: Space,
    first: u128,
    last: u128,
) -> Result<Vec<(u64, u128, u128)>> {
    let (_, width) = space.bits_width();
    let (range, _) = space.tables(t);
    let mut p = Vec::new();
    push_uint(&mut p, first, width);
    push_uint(&mut p, last, width);
    let mut out = Vec::new();
    for item in range.prefix_iter(txn, &p)? {
        let (k, _) = item?;
        out.push((
            id_from_tail(k).ok_or(StoreError::Corrupt("index key"))?,
            first,
            last,
        ));
    }
    Ok(out)
}

/// Objects whose range contains `[first, last]`, including an exact match
/// (`ip_first <= first AND ip_last >= last`).
pub(crate) fn ids_range_less_specific(
    t: &Tables,
    txn: &RoTxn<'_>,
    space: Space,
    first: u128,
    last: u128,
) -> Result<Vec<(u64, u128, u128)>> {
    let (bits, width) = space.bits_width();
    let (_, cover) = space.tables(t);
    let max_len = common_prefix_len(first, last, bits);
    let mut out = Vec::new();
    for len in 0..=max_len {
        let mut p = Vec::with_capacity(width + 1);
        p.push(len);
        push_uint(&mut p, mask(first, len, bits), width);
        for item in cover.prefix_iter(txn, &p)? {
            let (k, v) = item?;
            let f = read_uint(v, width).ok_or(StoreError::Corrupt("index value"))?;
            let l = read_uint(&v[width..], width).ok_or(StoreError::Corrupt("index value"))?;
            if f <= first && l >= last {
                out.push((
                    id_from_tail(k).ok_or(StoreError::Corrupt("index key"))?,
                    f,
                    l,
                ));
            }
        }
    }
    Ok(out)
}

/// Objects whose range lies inside `[first, last]`, excluding an exact
/// match (v4's non-prefix `ip_more_specific`).
pub(crate) fn ids_range_more_specific(
    t: &Tables,
    txn: &RoTxn<'_>,
    space: Space,
    first: u128,
    last: u128,
) -> Result<Vec<(u64, u128, u128)>> {
    let (_, width) = space.bits_width();
    let (range, _) = space.tables(t);
    let mut lo = Vec::new();
    push_uint(&mut lo, first, width);
    let mut hi = Vec::new();
    push_uint(&mut hi, last, width);
    hi.extend_from_slice(&[0xFF; 25]);
    let bounds = (
        std::ops::Bound::Included(lo.as_slice()),
        std::ops::Bound::Included(hi.as_slice()),
    );
    let mut out = Vec::new();
    for item in range.range(txn, &bounds)? {
        let (k, _) = item?;
        let f = read_uint(k, width).ok_or(StoreError::Corrupt("index key"))?;
        let l = read_uint(&k[width..], width).ok_or(StoreError::Corrupt("index key"))?;
        if l <= last && l >= first && !(f == first && l == last) {
            out.push((
                id_from_tail(k).ok_or(StoreError::Corrupt("index key"))?,
                f,
                l,
            ));
        }
    }
    Ok(out)
}

/// Objects whose `asn_first` is `asn` (any `asn_last`).
pub(crate) fn ids_asn_first(t: &Tables, txn: &RoTxn<'_>, asn: u32) -> Result<Vec<u64>> {
    let p = asn.to_be_bytes();
    let mut out = Vec::new();
    for item in t.asn_range.prefix_iter(txn, &p)? {
        let (k, _) = item?;
        out.push(id_from_tail(k).ok_or(StoreError::Corrupt("index key"))?);
    }
    Ok(out)
}

/// One route(6) object found by origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginRoute {
    /// The object's internal id.
    pub id: u64,
    /// `ip_first`
    pub ip_first: IpAddr,
    /// `prefix_length`
    pub prefix_length: u8,
    /// `rpki_status`
    pub rpki_status: RpkiStatus,
    /// `scopefilter_status`
    pub scopefilter_status: ScopeFilterStatus,
    /// `route_preference_status`
    pub route_preference_status: RoutePreferenceStatus,
}

/// Route and route6 objects in `source` with origin `asn`, optionally
/// limited to one IP version, in (version, address, length) order.
pub(crate) fn routes_for_origin(
    t: &Tables,
    txn: &RoTxn<'_>,
    source: &str,
    asn: u32,
    ip_version: Option<u8>,
) -> Result<Vec<OriginRoute>> {
    let mut p = Vec::new();
    push_str(&mut p, source.as_bytes());
    p.extend_from_slice(&asn.to_be_bytes());
    if let Some(v) = ip_version {
        p.push(v);
    }
    let base = p.len() - usize::from(ip_version.is_some());
    let mut out = Vec::new();
    for item in t.route_origin.prefix_iter(txn, &p)? {
        let (k, v) = item?;
        let rest = &k[base..];
        let ver = rest[0];
        let width = if ver == 4 { 4 } else { 16 };
        let addr = read_uint(&rest[1..], width).ok_or(StoreError::Corrupt("index key"))?;
        let ip = if ver == 4 {
            IpAddr::V4(std::net::Ipv4Addr::from(addr as u32))
        } else {
            IpAddr::V6(std::net::Ipv6Addr::from(addr))
        };
        let len = *rest
            .get(1 + width)
            .ok_or(StoreError::Corrupt("index key"))?;
        let (rpki, sf, rp) = statuses_from_bytes(v).ok_or(StoreError::Corrupt("index value"))?;
        out.push(OriginRoute {
            id: id_from_tail(k).ok_or(StoreError::Corrupt("index key"))?,
            ip_first: ip,
            prefix_length: len,
            rpki_status: rpki,
            scopefilter_status: sf,
            route_preference_status: rp,
        });
    }
    Ok(out)
}
