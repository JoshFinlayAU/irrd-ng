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

/// A `config::Value` as the query engine's [`query::ConfigValue`].
pub(crate) fn config_value(v: &Value) -> query::ConfigValue {
    use query::ConfigValue as C;
    match v {
        Value::None => C::Null,
        Value::Bool(b) => C::Bool(*b),
        Value::Int(i) => i
            .to_string()
            .parse::<i128>()
            .map(C::Int)
            .unwrap_or_else(|_| C::Str(i.to_string())),
        Value::Float(f) => C::Float(*f),
        Value::Str(s) => C::Str(s.clone()),
        Value::List(l) | Value::Tuple(l) | Value::Set(l) => {
            C::List(l.iter().map(config_value).collect())
        }
        Value::Dict(d) => C::Dict(
            d.iter()
                .map(|(k, v)| (k.py_str(), config_value(v)))
                .collect(),
        ),
        other => C::Str(other.py_str()),
    }
}

/// An integer setting (`int(get_setting(name))`), from an int or a string
/// (environment overrides are strings).
pub(crate) fn int_setting(cfg: &Configuration, name: &str) -> Option<i64> {
    setting(cfg, name).as_ref().and_then(int_of)
}

/// A string setting.
pub(crate) fn str_setting(cfg: &Configuration, name: &str) -> Option<String> {
    match setting(cfg, name)? {
        Value::None => None,
        Value::Str(s) => Some(s),
        other => Some(other.py_str()),
    }
}

fn str_list(v: Option<Value>) -> Vec<String> {
    match v {
        Some(Value::List(l) | Value::Tuple(l) | Value::Set(l)) => {
            l.iter().map(Value::py_str).collect()
        }
        Some(Value::Str(s)) => vec![s],
        _ => Vec::new(),
    }
}

/// The whois engine's settings.
pub(crate) fn query_settings(cfg: &Configuration) -> query::QuerySettings {
    let mut per_source = HashMap::new();
    let sources = configured_sources(cfg);
    for name in &sources {
        let k = |key: &str| format!("sources.{name}.{key}");
        per_source.insert(
            name.clone(),
            query::SourceQuerySettings {
                authoritative: setting(cfg, &k("authoritative"))
                    .as_ref()
                    .map(config_value)
                    .unwrap_or(query::ConfigValue::Bool(false)),
                keep_journal: setting(cfg, &k("keep_journal"))
                    .as_ref()
                    .map(config_value)
                    .unwrap_or(query::ConfigValue::Bool(false)),
                object_class_filter: object_class_filter(cfg, name),
                rpki_excluded: truthy(cfg, &k("rpki_excluded")),
                scopefilter_excluded: truthy(cfg, &k("scopefilter_excluded")),
                route_object_preference: setting(cfg, &k("route_object_preference"))
                    .as_ref()
                    .map(config_value)
                    .unwrap_or_default(),
                nrtm_host: truthy(cfg, &k("nrtm_host")),
                nrtm_access_list: str_setting(cfg, &k("nrtm_access_list")),
                nrtm_access_list_unfiltered: str_setting(cfg, &k("nrtm_access_list_unfiltered")),
            },
        );
    }
    let mut source_aliases = Vec::new();
    if let Some(Value::Dict(d)) = setting(cfg, "source_aliases") {
        for (k, v) in d.iter() {
            source_aliases.push((k.py_str(), str_list(Some(v.clone()))));
        }
    }
    let mut access_lists = HashMap::new();
    if let Some(Value::Dict(d)) = setting(cfg, "access_lists") {
        for (k, v) in d.iter() {
            let entries: Vec<rpsl::Ip> = str_list(Some(v.clone()))
                .iter()
                .filter_map(|e| rpsl::Ip::parse(e, 0).ok())
                .collect();
            access_lists.insert(k.py_str(), entries);
        }
    }
    query::QuerySettings {
        version: crate::IRRD_VERSION.to_owned(),
        sources,
        rpki_enabled: truthy(cfg, "rpki.roa_source"),
        source_aliases,
        sources_default: str_list(setting(cfg, "sources_default")),
        per_source,
        scopefilter_enabled: truthy(cfg, "scopefilter"),
        ipv4_only_route_set_members: truthy(cfg, "compatibility.ipv4_only_route_set_members"),
        inetnum_search_disabled: truthy(cfg, "compatibility.inetnum_search_disabled"),
        asdot_queries: truthy(cfg, "compatibility.asdot_queries"),
        access_lists,
        whois_access_list: str_setting(cfg, "server.whois.access_list"),
    }
}

/// `int(value)` for a setting, with Python's error text.
fn py_int_of(v: &Value) -> Result<i64, String> {
    match v {
        Value::Int(i) => i
            .to_string()
            .parse()
            .map_err(|_| format!("int too large: {i}")),
        Value::Bool(b) => Ok(i64::from(*b)),
        Value::Float(f) => Ok(f.trunc() as i64),
        Value::Str(s) => crate::argparse::py_int(s).ok_or_else(|| {
            format!(
                "invalid literal for int() with base 10: {}",
                config::str_repr(s)
            )
        }),
        other => Err(format!(
            "int() argument must be a string, a bytes-like object or a real number, not '{}'",
            other.type_name()
        )),
    }
}

/// `int(get_setting(name, default))`.
fn int_setting_or(cfg: &Configuration, name: &str, default: i64) -> Result<i64, String> {
    match setting(cfg, name) {
        None | Some(Value::None) => Ok(default),
        Some(v) => py_int_of(&v),
    }
}

/// `email.*`, for `send_email`.
pub(crate) fn mail_settings(cfg: &Configuration) -> mail::MailSettings {
    let opt = |name: &str| setting(cfg, name).filter(Value::truthy).map(|v| v.py_str());
    mail::MailSettings {
        from: opt("email.from"),
        smtp: opt("email.smtp"),
        footer: setting(cfg, "email.footer")
            .filter(|v| !matches!(v, Value::None))
            .map(|v| v.py_str())
            .unwrap_or_default(),
        recipient_override: opt("email.recipient_override"),
    }
}

/// The ROA import, scope filter and route preference jobs' settings.
pub(crate) fn status_job_settings(
    cfg: &Configuration,
) -> nrtm::mirror::status_jobs::StatusJobSettings {
    use nrtm::mirror::status_jobs::{ScopeFilterFingerprint, StatusJobSettings};
    let opt = |name: &str| setting(cfg, name).filter(Value::truthy).map(|v| v.py_str());
    let text = |name: &str| setting(cfg, name).map(|v| v.py_str()).unwrap_or_default();
    let sources_dict = match cfg.user_config().get_str("sources") {
        Some(Value::Dict(d)) => Some(d.clone()),
        _ => None,
    };
    let raw_source_flag = |key: &str| -> Vec<String> {
        let mut out = Vec::new();
        if let Some(d) = &sources_dict {
            for (k, v) in d.iter() {
                if let (Some(name), Value::Dict(sd)) = (k.as_str(), v)
                    && sd.get_str(key).is_some_and(Value::truthy)
                {
                    out.push(name.to_owned());
                }
            }
        }
        out
    };
    let mut authoritative_sources = HashSet::new();
    for name in configured_sources(cfg) {
        if truthy(cfg, &format!("sources.{name}.authoritative")) {
            authoritative_sources.insert(name);
        }
    }
    let items = |name: &str| -> Vec<String> {
        match setting(cfg, name) {
            Some(Value::List(l)) | Some(Value::Tuple(l)) => l.iter().map(Value::py_repr).collect(),
            Some(Value::None) | None => Vec::new(),
            Some(other) => other
                .py_iter()
                .map(|v| v.iter().map(Value::py_repr).collect())
                .unwrap_or_default(),
        }
    };
    let scopefilter = truthy(cfg, "scopefilter").then(|| ScopeFilterFingerprint {
        prefixes: items("scopefilter.prefixes"),
        asns: items("scopefilter.asns"),
        excluded: raw_source_flag("scopefilter_excluded")
            .into_iter()
            .collect(),
    });
    StatusJobSettings {
        roa_source: opt("rpki.roa_source"),
        slurm_source: opt("rpki.slurm_source"),
        roa_import_timer: int_setting_or(cfg, "rpki.roa_import_timer", 3600).unwrap_or(3600),
        pseudo_irr_remarks: text("rpki.pseudo_irr_remarks"),
        notify: rpki::notifications::NotifySettings {
            enabled: truthy(cfg, "rpki.notify_invalid_enabled"),
            authoritative_sources,
            subject: text("rpki.notify_invalid_subject"),
            header: text("rpki.notify_invalid_header"),
        },
        mail: mail_settings(cfg),
        route_preference_enabled: !raw_source_flag("route_object_preference").is_empty(),
        route_preference_update_timer: int_setting_or(
            cfg,
            "route_object_preference.update_timer",
            3600,
        )
        .unwrap_or(3600),
        scopefilter,
    }
}

/// The mirroring client's settings.
pub(crate) fn mirror_settings(cfg: &Configuration) -> nrtm::mirror::settings::MirrorSettings {
    use nrtm::mirror::settings::{self as ms, MirrorSettings, SourceMirrorSettings};
    let fast_scheduler =
        std::env::var_os("IRRD_TESTING_FAST_SCHEDULER_OVERRIDE").is_some_and(|v| !v.is_empty());
    let mut out = MirrorSettings {
        readonly_standby: truthy(cfg, "readonly_standby"),
        rpki_enabled: truthy(cfg, "rpki.roa_source"),
        rpki_excluded_sources: rpki_excluded_sources(cfg),
        scopefilter: scopefilter_config(cfg),
        rpsl: cfg.rpsl_settings().unwrap_or_default(),
        download_timeout: int_setting_or(cfg, "download_timeout", 10)
            .unwrap_or(10)
            .max(0) as u64,
        fast_scheduler,
        sources: Vec::new(),
        status_jobs: status_job_settings(cfg),
    };
    let nrtm4_timer = out.default_import_timer_nrtm4();
    for name in configured_sources(cfg) {
        let k = |key: &str| format!("sources.{name}.{key}");
        let truthy_str = |key: &str| {
            setting(cfg, &k(key))
                .filter(Value::truthy)
                .map(|v| v.py_str())
        };
        let import_value = setting(cfg, &k("import_source"));
        let (import_source, import_source_repr) = match import_value {
            Some(v) if v.truthy() => {
                let list = match v {
                    Value::Str(s) => Value::List(vec![Value::Str(s)]),
                    other => other,
                };
                let items = match &list {
                    Value::List(l) | Value::Tuple(l) | Value::Set(l) => {
                        l.iter().map(Value::py_str).collect()
                    }
                    other => vec![other.py_str()],
                };
                (Some(items), list.py_str())
            }
            Some(v) => (None, v.py_str()),
            None => (None, "None".to_owned()),
        };
        let serial_value = setting(cfg, &k("import_serial_source"));
        let initial_key = truthy_str("nrtm4_client_initial_public_key");
        let default_timer = if initial_key.is_some() {
            nrtm4_timer
        } else {
            ms::DEFAULT_SOURCE_IMPORT_TIMER
        };
        out.sources.push(SourceMirrorSettings {
            name: name.clone(),
            import_source,
            import_source_repr,
            import_serial_source: serial_value
                .as_ref()
                .filter(|v| v.truthy())
                .map(Value::py_str),
            import_serial_source_str: serial_value
                .as_ref()
                .map_or_else(|| "None".to_owned(), Value::py_str),
            nrtm_host: truthy_str("nrtm_host"),
            nrtm_port: int_setting_or(cfg, &k("nrtm_port"), ms::DEFAULT_SOURCE_NRTM_PORT),
            nrtm3_client_timeout: int_setting_or(
                cfg,
                &k("nrtm3_client_timeout"),
                ms::DEFAULT_SOURCE_NRTM3_CLIENT_TIMEOUT,
            ),
            import_timer: int_setting_or(cfg, &k("import_timer"), default_timer)
                .unwrap_or(default_timer),
            nrtm4_client_notification_file_url: truthy_str("nrtm4_client_notification_file_url"),
            nrtm4_client_initial_public_key: initial_key,
            object_class_filter: object_class_filter(cfg, &name),
            strict_import_keycert_objects: truthy(cfg, &k("strict_import_keycert_objects")),
            rpki_excluded: truthy(cfg, &k("rpki_excluded")),
            runs_rpsl_export: truthy(cfg, &k("export_destination"))
                || truthy(cfg, &k("export_destination_unfiltered")),
            export_timer: int_setting_or(cfg, &k("export_timer"), ms::DEFAULT_SOURCE_EXPORT_TIMER)
                .unwrap_or(ms::DEFAULT_SOURCE_EXPORT_TIMER),
            runs_nrtm4_server: truthy(cfg, &k("nrtm4_server_private_key")),
        });
    }
    out
}
