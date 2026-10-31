//! Settings the tools read from `irrd.yaml`, as v4 reads them with
//! `get_setting()` (environment overrides included).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use config::{Configuration, Value};
use store::{IpPrefix, SourceSettings, StoreSettings};

/// Where the store lives. irrd-ng has no Postgres; the environment variable
/// `IRRD_NG_STORE_PATH` names the directory, defaulting to
/// `/var/lib/irrd-ng`.
pub(crate) fn store_path() -> PathBuf {
    std::env::var_os("IRRD_NG_STORE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/irrd-ng"))
}

pub(crate) fn setting(cfg: &Configuration, name: &str) -> Option<Value> {
    cfg.get_setting_live(name)
        .ok()
        .flatten()
        .map(|v| v.into_owned())
}

pub(crate) fn truthy(cfg: &Configuration, name: &str) -> bool {
    setting(cfg, name).is_some_and(|v| v.truthy())
}

fn int_of(v: &Value) -> Option<i64> {
    match v {
        Value::Int(i) => i.to_string().parse().ok(),
        Value::Bool(b) => Some(i64::from(*b)),
        Value::Str(s) => crate::argparse::py_int(s),
        _ => None,
    }
}

/// Names of the sources in the file, in file order.
pub(crate) fn configured_sources(cfg: &Configuration) -> Vec<String> {
    match cfg.user_config().get_str("sources") {
        Some(Value::Dict(d)) => d
            .keys()
            .filter_map(|k| k.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// The store's settings.
pub(crate) fn store_settings(cfg: &Configuration) -> StoreSettings {
    let mut sources = HashMap::new();
    for name in configured_sources(cfg) {
        let k = |key: &str| format!("sources.{name}.{key}");
        sources.insert(
            name.clone(),
            SourceSettings {
                keep_journal: truthy(cfg, &k("keep_journal")),
                nrtm_host: truthy(cfg, &k("nrtm_host")),
                rpki_excluded: truthy(cfg, &k("rpki_excluded")),
                scopefilter_excluded: truthy(cfg, &k("scopefilter_excluded")),
                route_object_preference: setting(cfg, &k("route_object_preference"))
                    .as_ref()
                    .and_then(int_of),
            },
        );
    }
    StoreSettings {
        sources,
        scopefilter_enabled: truthy(cfg, "scopefilter"),
        rpki_enabled: truthy(cfg, "rpki.roa_source"),
        readonly_standby: truthy(cfg, "readonly_standby"),
    }
}

/// `get_object_class_filter_for_source(source)`.
pub(crate) fn object_class_filter(cfg: &Configuration, source: &str) -> Option<Vec<String>> {
    let v = setting(cfg, &format!("sources.{source}.object_class_filter"))?;
    if !v.truthy() {
        return None;
    }
    let items = match v {
        Value::Str(s) => vec![s],
        Value::List(l) | Value::Tuple(l) => l.into_iter().map(|i| i.py_str()).collect(),
        other => vec![other.py_str()],
    };
    Some(
        items
            .into_iter()
            .map(|c| rpsl::text::py_strip(&c).to_lowercase())
            .collect(),
    )
}

/// Sources whose settings dict has a truthy `rpki_excluded`
/// (`BulkRouteROAValidator` reads the dict, not `get_setting`).
pub(crate) fn rpki_excluded_sources(cfg: &Configuration) -> HashSet<String> {
    let mut out = HashSet::new();
    if let Some(Value::Dict(d)) = cfg.user_config().get_str("sources") {
        for (k, v) in d.iter() {
            if let (Some(name), Value::Dict(s)) = (k.as_str(), v)
                && s.get_str("rpki_excluded").is_some_and(Value::truthy)
            {
                out.insert(name.to_owned());
            }
        }
    }
    out
}

/// `ScopeFilterValidator.load_filters()`.
pub(crate) fn scopefilter_config(cfg: &Configuration) -> rpki::ScopeFilterConfig {
    let mut c = rpki::ScopeFilterConfig::default();
    if let Some(Value::List(prefixes)) = setting(cfg, "scopefilter.prefixes") {
        for p in prefixes {
            if let Ok(ip) = rpsl::Ip::parse(&p.py_str(), 0) {
                let addr = if ip.version() == 4 {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip.int() as u32))
                } else {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip.int()))
                };
                if let Some(pf) = IpPrefix::new(addr, ip.prefixlen() as u8) {
                    c.prefixes.push(pf);
                }
            }
        }
    }
    if let Some(Value::List(asns)) = setting(cfg, "scopefilter.asns") {
        for a in asns {
            let s = a.py_str();
            if let Some((start, end)) = s.split_once('-') {
                if let (Some(x), Some(y)) =
                    (crate::argparse::py_int(start), crate::argparse::py_int(end))
                {
                    c.asn_ranges.push((x as u64, y as u64));
                }
            } else if let Some(x) = crate::argparse::py_int(&s) {
                c.asns.insert(x as u64);
            }
        }
    }
    for name in configured_sources(cfg) {
        c.excluded_sources.insert(
            name.clone(),
            truthy(cfg, &format!("sources.{name}.scopefilter_excluded")),
        );
    }
    c
}
