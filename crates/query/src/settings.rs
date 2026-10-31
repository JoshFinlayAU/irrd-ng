//! The settings the query engine reads, as v4 reads them with
//! `get_setting()`. The caller (the daemon) builds a [`QuerySettings`] from
//! `irrd.yaml`; the engine itself has no configuration dependency.

use std::collections::HashMap;
use std::fmt::Write as _;

use rpsl::Ip;

/// A configuration value v4 copies into a response unchanged (`!J`
/// reports `authoritative`, `keep_journal` and `route_object_preference`
/// as configured, not as booleans).
#[derive(Debug, Clone, PartialEq, Default)]
pub enum ConfigValue {
    /// `None`
    #[default]
    Null,
    /// `bool`
    Bool(bool),
    /// `int`
    Int(i128),
    /// `float`
    Float(f64),
    /// `str`
    Str(String),
    /// `list`
    List(Vec<ConfigValue>),
    /// `dict`, in insertion order.
    Dict(Vec<(String, ConfigValue)>),
}

impl ConfigValue {
    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            ConfigValue::Null => false,
            ConfigValue::Bool(b) => *b,
            ConfigValue::Int(i) => *i != 0,
            ConfigValue::Float(f) => *f != 0.0,
            ConfigValue::Str(s) => !s.is_empty(),
            ConfigValue::List(l) => !l.is_empty(),
            ConfigValue::Dict(d) => !d.is_empty(),
        }
    }

    /// Append the value as `ujson.dumps` writes it at `indent=4`, nested
    /// `depth` levels deep.
    pub(crate) fn write_ujson(&self, out: &mut String, depth: usize) {
        match self {
            ConfigValue::Null => out.push_str("null"),
            ConfigValue::Bool(true) => out.push_str("true"),
            ConfigValue::Bool(false) => out.push_str("false"),
            ConfigValue::Int(i) => {
                let _ = write!(out, "{i}");
            }
            ConfigValue::Float(f) => crate::json::write_float(out, *f),
            ConfigValue::Str(s) => crate::json::write_str(out, s),
            ConfigValue::List(items) => {
                crate::json::write_list(out, depth, items.iter(), |o, v, d| v.write_ujson(o, d))
            }
            ConfigValue::Dict(items) => {
                if items.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push('{');
                for (i, (k, v)) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    crate::json::newline(out, depth + 1);
                    crate::json::write_str(out, k);
                    out.push_str(": ");
                    v.write_ujson(out, depth + 1);
                }
                crate::json::newline(out, depth);
                out.push('}');
            }
        }
    }
}

/// Per-source settings (`sources.<name>.*`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SourceQuerySettings {
    /// `authoritative`, as configured (`False` when unset).
    pub authoritative: ConfigValue,
    /// `keep_journal`, as configured (`False` when unset).
    pub keep_journal: ConfigValue,
    /// `get_object_class_filter_for_source()`.
    pub object_class_filter: Option<Vec<String>>,
    /// `rpki_excluded`
    pub rpki_excluded: bool,
    /// `scopefilter_excluded`
    pub scopefilter_excluded: bool,
    /// `route_object_preference`, as configured (`None` when unset).
    pub route_object_preference: ConfigValue,
    /// `nrtm_host` is set.
    pub nrtm_host: bool,
    /// `nrtm_access_list`
    pub nrtm_access_list: Option<String>,
    /// `nrtm_access_list_unfiltered`
    pub nrtm_access_list_unfiltered: Option<String>,
    /// `nrtm_query_serial_range_limit`, as configured.
    pub nrtm_query_serial_range_limit: ConfigValue,
    /// `nrtm_query_serial_days_limit`, as configured.
    pub nrtm_query_serial_days_limit: ConfigValue,
    /// `nrtm_response_header`, when truthy.
    pub nrtm_response_header: Option<String>,
    /// The `nrtm_dummified_*` settings.
    pub dummify: rpsl::text::DummifySettings,
}

/// Everything the whois engine reads from `irrd.yaml`.
#[derive(Debug, Clone, Default)]
pub struct QuerySettings {
    /// IRRd's version, as `!v` reports it.
    pub version: String,
    /// The names under `sources`, in file order.
    pub sources: Vec<String>,
    /// `rpki.roa_source` is set: RPKI-aware, with the `RPKI` pseudo source.
    pub rpki_enabled: bool,
    /// `source_aliases`, in file order.
    pub source_aliases: Vec<(String, Vec<String>)>,
    /// `sources_default`
    pub sources_default: Vec<String>,
    /// Settings per configured source.
    pub per_source: HashMap<String, SourceQuerySettings>,
    /// `scopefilter` is set.
    pub scopefilter_enabled: bool,
    /// `compatibility.ipv4_only_route_set_members`
    pub ipv4_only_route_set_members: bool,
    /// `compatibility.inetnum_search_disabled`
    pub inetnum_search_disabled: bool,
    /// `compatibility.asdot_queries`
    pub asdot_queries: bool,
    /// `access_lists`, parsed. A missing or empty list is absent.
    pub access_lists: HashMap<String, Vec<Ip>>,
    /// `server.whois.access_list`
    pub whois_access_list: Option<String>,
}

static DEFAULT_SOURCE: std::sync::LazyLock<SourceQuerySettings> =
    std::sync::LazyLock::new(|| SourceQuerySettings {
        authoritative: ConfigValue::Bool(false),
        keep_journal: ConfigValue::Bool(false),
        ..SourceQuerySettings::default()
    });

/// `RPKI_IRR_PSEUDO_SOURCE`
pub const RPKI_IRR_PSEUDO_SOURCE: &str = "RPKI";

impl QuerySettings {
    /// The settings of a source, or the defaults `get_setting()` would
    /// return for one that is not configured.
    pub fn source(&self, name: &str) -> &SourceQuerySettings {
        self.per_source.get(name).unwrap_or(&DEFAULT_SOURCE)
    }

    /// `QuerySourceManager.all_valid_real_sources`.
    pub fn all_valid_real_sources(&self) -> impl Iterator<Item = &str> {
        self.sources
            .iter()
            .map(String::as_str)
            .chain(self.rpki_enabled.then_some(RPKI_IRR_PSEUDO_SOURCE))
    }

    pub(crate) fn is_valid_real_source(&self, name: &str) -> bool {
        self.all_valid_real_sources().any(|s| s == name)
    }

    pub(crate) fn alias(&self, name: &str) -> Option<&[String]> {
        self.source_aliases
            .iter()
            .find(|(a, _)| a == name)
            .map(|(_, v)| v.as_slice())
    }

    /// `all_valid_sources`: real sources, then aliases.
    pub(crate) fn all_valid_sources(&self) -> Vec<String> {
        self.all_valid_real_sources()
            .map(str::to_owned)
            .chain(self.source_aliases.iter().map(|(a, _)| a.clone()))
            .collect()
    }

    pub(crate) fn is_valid_source(&self, name: &str) -> bool {
        self.is_valid_real_source(name) || self.alias(name).is_some()
    }

    /// `is_client_permitted(ip, access_list_setting, default_deny)`
    /// (`irrd/server/access_check.py`), for an access list name read from
    /// the setting. `None` means v4 could not read the client address.
    pub fn is_client_permitted(
        &self,
        ip: &str,
        access_list_name: Option<&str>,
        default_deny: bool,
    ) -> Option<bool> {
        let client = Ip::parse(ip, 0).ok()?;
        let client = v46map(client);
        let list = access_list_name.and_then(|n| self.access_lists.get(n));
        let Some(list) = list.filter(|l| !l.is_empty()) else {
            return Some(!default_deny);
        };
        Some(list.iter().any(|allowed| ip_contains(allowed, &client)))
    }
}

/// `IP.v46map()` where it succeeds for an IPv6 address.
fn v46map(ip: Ip) -> Ip {
    const MAP_MASK: u128 = 0xffff_0000_0000;
    const TEST_MAP: u128 = !0xffff_ffff_u128;
    if ip.version() == 6 && ip.int() & TEST_MAP == MAP_MASK {
        let len = ip.prefixlen().saturating_sub(96);
        let text = format!("{}/{len}", ip.int() - MAP_MASK);
        if let Ok(v4) = Ip::parse(&text, 0) {
            return v4;
        }
    }
    ip
}

/// `item in IP(...)` for an `IP` item (`IPint.__contains__`).
fn ip_contains(net: &Ip, item: &Ip) -> bool {
    if item.version() != net.version() {
        return false;
    }
    let len = |ip: &Ip| -> u128 {
        let bits = if ip.version() == 4 { 32 } else { 128 };
        let host = bits - ip.prefixlen();
        if host >= 128 {
            u128::MAX
        } else {
            1u128 << host
        }
    };
    let span = len(net).saturating_sub(len(item));
    item.int() >= net.int() && item.int() <= net.int().saturating_add(span)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_with_list(entries: &[&str]) -> QuerySettings {
        let mut s = QuerySettings::default();
        s.access_lists.insert(
            "l".into(),
            entries
                .iter()
                .map(|e| Ip::parse(e, 0).expect("prefix"))
                .collect(),
        );
        s
    }

    #[test]
    fn access_lists_like_v4() {
        let s = settings_with_list(&["192.0.2.0/24", "2001:db8::/32"]);
        assert_eq!(
            s.is_client_permitted("192.0.2.1", Some("l"), true),
            Some(true)
        );
        assert_eq!(
            s.is_client_permitted("192.0.3.1", Some("l"), true),
            Some(false)
        );
        assert_eq!(
            s.is_client_permitted("::ffff:192.0.2.9", Some("l"), true),
            Some(true)
        );
        assert_eq!(
            s.is_client_permitted("2001:db8::1", Some("l"), true),
            Some(true)
        );
        assert_eq!(
            s.is_client_permitted("2001:db9::1", Some("l"), true),
            Some(false)
        );
        assert_eq!(s.is_client_permitted("192.0.2.1", None, true), Some(false));
        assert_eq!(s.is_client_permitted("192.0.2.1", None, false), Some(true));
        assert_eq!(
            s.is_client_permitted("192.0.2.1", Some("x"), false),
            Some(true)
        );
        assert_eq!(s.is_client_permitted("not-an-ip", Some("l"), true), None);
    }
}
