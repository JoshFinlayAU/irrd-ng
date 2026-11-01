//! The `RPSLDatabaseQuery` shapes the update handlers use, on a write
//! transaction (which sees its own uncommitted changes, as v4's queries
//! inside its transaction do). v4's default query has no visibility filter:
//! RPKI invalid, out of scope and suppressed objects count here too.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rpsl::{ParseOptions, RpslObject, Value};
use store::{RpslObjectRef, Space, Uuid, WriteTx};

use crate::Internal;
use crate::settings::SubmitSettings;

/// An owned `rpsl_objects` row, with what v4's ordering needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    pub(crate) id: u64,
    pub(crate) pk: Uuid,
    pub(crate) rpsl_pk: String,
    pub(crate) source: String,
    pub(crate) object_class: String,
    pub(crate) parsed_data: String,
    pub(crate) object_text: String,
    pub(crate) ip_first: Option<IpAddr>,
    pub(crate) ip_last: Option<IpAddr>,
    pub(crate) asn_first: Option<u32>,
}

impl Row {
    fn of(id: u64, o: &RpslObjectRef<'_>) -> Row {
        Row {
            id,
            pk: o.pk,
            rpsl_pk: o.rpsl_pk.to_owned(),
            source: o.source.to_owned(),
            object_class: o.object_class.to_owned(),
            parsed_data: o.parsed_data.to_owned(),
            object_text: o.object_text.to_owned(),
            ip_first: o.ip_first,
            ip_last: o.ip_last,
            asn_first: o.asn_first,
        }
    }

    /// `parsed_data.get(key, [])` as a list.
    pub(crate) fn list(&self, key: &str) -> Vec<String> {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&self.parsed_data) else {
            return Vec::new();
        };
        match v.get(key) {
            Some(serde_json::Value::Array(a)) => a
                .iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect(),
            Some(serde_json::Value::String(s)) => vec![s.clone()],
            _ => Vec::new(),
        }
    }

    fn order_key(&self) -> query::order::OrderKey<'_> {
        query::order::OrderKey {
            ip_first: self.ip_first,
            asn_first: self.asn_first,
            rpsl_pk: &self.rpsl_pk,
            id: self.id,
        }
    }
}

/// Sort rows in v4's default query order.
pub(crate) fn sort_v4(rows: &mut [Row]) {
    rows.sort_by(|a, b| a.order_key().v4_cmp(&b.order_key()));
}

/// `str.upper().strip()`, as `rpsl_pks()` normalises its values.
pub(crate) fn upper_strip(s: &str) -> String {
    rpsl::python::strip(&rpsl::python::upper(s)).to_owned()
}

/// `rpsl_obj.source()`; v4 raises `ValueError` without one.
pub(crate) fn source_of(obj: &RpslObject) -> Result<String, Internal> {
    obj.source()
        .map(str::to_owned)
        .map_err(|e| Internal(e.to_string()))
}

/// `parsed_data["mnt-by"]`; a `KeyError` in v4 without one.
pub(crate) fn mnt_by(obj: &RpslObject) -> Result<Vec<String>, Internal> {
    match obj.parsed_value("mnt-by") {
        Some(Value::List(l)) => Ok(l.clone()),
        Some(Value::Str(s)) => Ok(s.chars().map(String::from).collect()),
        None => Err(Internal("'mnt-by'".to_owned())),
    }
}

/// `parsed_data.get(attr, [])` of a parsed object, as a list.
pub(crate) fn attr_list(obj: &RpslObject, attr: &str) -> Vec<String> {
    match obj.parsed_value(attr) {
        Some(Value::List(l)) => l.clone(),
        Some(Value::Str(s)) => s.chars().map(String::from).collect(),
        None => Vec::new(),
    }
}

/// `rpsl_object_from_text(text, strict_validation=False)` on stored text.
pub(crate) fn parse_stored(text: &str, settings: &SubmitSettings) -> Result<RpslObject, Internal> {
    let keyring = rpsl::Keyring::new();
    rpsl::rpsl_object_from_text(
        text,
        &ParseOptions {
            strict: false,
            default_source: None,
            settings: &settings.rpsl,
            keyring: &keyring,
        },
    )
    .map_err(|e| Internal(e.to_string()))
}

/// `RPSLDatabaseQuery().sources([source]).object_classes([class]).rpsl_pks(pks)`
pub(crate) fn objects_by_pks(
    tx: &mut WriteTx<'_, '_>,
    source: &str,
    class: &str,
    pks: &[&str],
) -> Result<Vec<Row>, Internal> {
    let view = tx.read()?;
    let mut rows = Vec::new();
    for pk in pks {
        let pk = upper_strip(pk);
        if let Some(id) = view.object_id(source, class, &pk)?
            && let Some(o) = view.object_by_id(id)?
            && !rows.iter().any(|r: &Row| r.id == id)
        {
            rows.push(Row::of(id, &o));
        }
    }
    sort_v4(&mut rows);
    Ok(rows)
}

/// `RPSLDatabaseQuery().sources([source]).lookup_attrs_in(attrs, [value])`
pub(crate) fn lookup_attrs_in(
    tx: &mut WriteTx<'_, '_>,
    source: &str,
    attrs: &[&str],
    value: &str,
) -> Result<Vec<Row>, Internal> {
    let view = tx.read()?;
    let upper = rpsl::python::upper(value);
    let mut ids: Vec<u64> = Vec::new();
    for attr in attrs {
        ids.extend(view.ids_by_lookup(attr, Some(&upper))?);
    }
    ids.sort_unstable();
    ids.dedup();
    let mut rows = Vec::new();
    for id in ids {
        if let Some(o) = view.object_by_id(id)?
            && o.source == source
        {
            rows.push(Row::of(id, &o));
        }
    }
    sort_v4(&mut rows);
    Ok(rows)
}

/// The address of an `rpsl::Ip`.
pub(crate) fn ip_of(ip: &rpsl::Ip) -> IpAddr {
    if ip.version() == 4 {
        IpAddr::V4(Ipv4Addr::from(ip.int() as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(ip.int()))
    }
}

/// An `rpsl::Ip` prefix as the store's prefix type.
pub(crate) fn store_prefix(ip: &rpsl::Ip) -> Option<store::IpPrefix> {
    store::IpPrefix::new(ip_of(ip), ip.prefixlen() as u8)
}

fn addr_u128(a: &IpAddr) -> u128 {
    match a {
        IpAddr::V4(v) => u128::from(u32::from(*v)),
        IpAddr::V6(v) => u128::from(*v),
    }
}

fn space(ip: &rpsl::Ip) -> Space {
    if ip.version() == 4 {
        Space::Ipv4
    } else {
        Space::Ipv6
    }
}

fn rows_in_class(
    tx: &mut WriteTx<'_, '_>,
    source: &str,
    class: &str,
    candidates: Vec<(u64, u128, u128)>,
) -> Result<Vec<Row>, Internal> {
    let view = tx.read()?;
    let mut rows = Vec::new();
    for (id, _, _) in candidates {
        if let Some(o) = view.object_by_id(id)?
            && o.source == source
            && o.object_class == class
            && !rows.iter().any(|r: &Row| r.id == id)
        {
            rows.push(Row::of(id, &o));
        }
    }
    Ok(rows)
}

/// `.ip_exact(prefix).first_only()` on one class of one source.
pub(crate) fn ip_exact(
    tx: &mut WriteTx<'_, '_>,
    source: &str,
    class: &str,
    prefix: &rpsl::Ip,
) -> Result<Option<Row>, Internal> {
    let (net, bcast) = (prefix.net().int(), prefix.broadcast().int());
    let candidates = tx.read()?.range_exact(space(prefix), net, bcast)?;
    let mut rows = rows_in_class(tx, source, class, candidates)?;
    rows.retain(|r| {
        r.ip_first.as_ref().map(addr_u128) == Some(net)
            && r.ip_last.as_ref().map(addr_u128) == Some(bcast)
    });
    sort_v4(&mut rows);
    Ok(rows.into_iter().next())
}

/// `.ip_less_specific_one_level(prefix)` with `first_only()` on one class
/// of one source: the smallest strictly covering objects, then v4's order.
pub(crate) fn ip_less_specific_one_level(
    tx: &mut WriteTx<'_, '_>,
    source: &str,
    class: &str,
    prefix: &rpsl::Ip,
) -> Result<Option<Row>, Internal> {
    let (net, bcast) = (prefix.net().int(), prefix.broadcast().int());
    let candidates = tx.read()?.range_less_specific(space(prefix), net, bcast)?;
    let mut rows = rows_in_class(tx, source, class, candidates)?;
    rows.retain(|r| {
        let (Some(f), Some(l)) = (&r.ip_first, &r.ip_last) else {
            return false;
        };
        let (f, l) = (addr_u128(f), addr_u128(l));
        f <= net && l >= bcast && !(f == net && l == bcast)
    });
    let size = |r: &Row| match (&r.ip_first, &r.ip_last) {
        (Some(a), Some(b)) => addr_u128(b).wrapping_sub(addr_u128(a)),
        _ => u128::MAX,
    };
    let Some(min) = rows.iter().map(size).min() else {
        return Ok(None);
    };
    rows.retain(|r| size(r) == min);
    sort_v4(&mut rows);
    Ok(rows.into_iter().next())
}
