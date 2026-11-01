//! `Configuration._check_staging_config` from `irrd/conf/__init__.py`.
//!
//! The checks run in v4's order and append v4's strings, so the error list
//! (and the `repr()` of it in the startup message) is identical. v4 operates
//! on whatever Python objects the YAML produced; where one of its checks
//! raises instead of appending an error, v4 crashes, and this returns the
//! exception it would have raised.

use std::path::Path;

use num_bigint::BigInt;

use crate::dotted;
use crate::eckey::{self, KeyError};
use crate::ipy::{self, IpError};
use crate::known_keys::{
    self, AUTNUM_AUTHENTICATION_MODES, KNOWN_FLEXIBLE_KEYS, PASSWORD_HASHER_AVAILABILITY,
};
use crate::messages;
use crate::python::{Dict, PyException, Value, int_of, str_isnumeric};
use crate::ratelimit;
use crate::urlparse::urlparse;

/// `RPKI_IRR_PSEUDO_SOURCE`.
pub(crate) const RPKI_IRR_PSEUDO_SOURCE: &str = "RPKI";

/// `DEFAULT_SOURCE_NRTM4_SERVER_SNAPSHOT_FREQUENCY` (`irrd/conf/defaults.py`).
pub(crate) const DEFAULT_SOURCE_NRTM4_SERVER_SNAPSHOT_FREQUENCY: i64 = 3600 * 4;

/// `NRTM4_SERVER_DELTA_EXPIRY_TIME` in seconds.
pub(crate) const NRTM4_SERVER_DELTA_EXPIRY_SECONDS: u64 = 24 * 3600;

type Result<T> = std::result::Result<T, PyException>;

/// `SOURCE_NAME_RE.match(name)`: `^[A-Z][A-Z0-9-]*[A-Z0-9]$`.
pub(crate) fn is_valid_source_name(name: &str) -> bool {
    let name = name.strip_suffix('\n').unwrap_or(name);
    let bytes = name.as_bytes();
    bytes.len() >= 2
        && bytes[0].is_ascii_uppercase()
        && (bytes[bytes.len() - 1].is_ascii_uppercase() || bytes[bytes.len() - 1].is_ascii_digit())
        && bytes[1..bytes.len() - 1]
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'-')
}

/// How the checks see the filesystem: `os.path.isdir` on a path.
pub(crate) type IsDir<'a> = &'a dyn Fn(&str) -> bool;

/// The real filesystem.
pub(crate) fn real_is_dir(path: &str) -> bool {
    Path::new(path).is_dir()
}

/// `os.path.isdir(value)`.
fn isdir(is_dir: IsDir<'_>, value: &Value) -> Result<bool> {
    match value {
        Value::Str(s) => Ok(is_dir(s)),
        Value::Bytes(b) => Ok(std::str::from_utf8(b).is_ok_and(is_dir)),
        // An int is a file descriptor to os.stat; none of v4's are directories.
        Value::Int(_) | Value::Bool(_) => Ok(false),
        other => Err(PyException::type_error(format!(
            "stat: path should be string, bytes, os.PathLike or integer, not {}",
            other.type_name()
        ))),
    }
}

/// Python's `', '.join(items)`.
fn join(sep: &str, items: &[Value]) -> Result<String> {
    let mut parts = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        match item {
            Value::Str(s) => parts.push(s.as_str()),
            other => {
                return Err(PyException::type_error(format!(
                    "sequence item {i}: expected str instance, {} found",
                    other.type_name()
                )));
            }
        }
    }
    Ok(parts.join(sep))
}

/// `dict.items()` on a value that must be a mapping.
fn items(value: &Value) -> Result<&Dict> {
    match value {
        Value::Dict(d) => Ok(d),
        other => Err(PyException::attribute_error(other, "items")),
    }
}

/// Python's `{...}` / `set.add`: values that compare equal collapse, lists
/// are distinct objects (DottedList hashes by identity), mappings raise.
#[derive(Default)]
struct PySet {
    items: Vec<Value>,
}

impl PySet {
    fn add(&mut self, value: &Value) -> Result<()> {
        match value {
            Value::Dict(_) | Value::Set(_) => Err(PyException::unhashable(value)),
            Value::List(_) => {
                self.items.push(value.clone());
                Ok(())
            }
            v => {
                if !self.contains(v)? {
                    self.items.push(v.clone());
                }
                Ok(())
            }
        }
    }

    fn contains(&self, value: &Value) -> Result<bool> {
        match value {
            Value::Dict(_) | Value::Set(_) => Err(PyException::unhashable(value)),
            Value::List(_) => Ok(false),
            v => Ok(self
                .items
                .iter()
                .any(|i| !matches!(i, Value::List(_)) && i.py_eq(v))),
        }
    }
}

struct Checker<'a> {
    config: &'a Dict,
    is_dir: IsDir<'a>,
    errors: Vec<String>,
}

impl<'a> Checker<'a> {
    fn get(&self, key: &str) -> Result<Option<&'a Value>> {
        dotted::get(self.config, key)
    }

    /// `_check_is_str(config, key, required=True)`.
    fn is_str_required(&self, key: &str) -> Result<bool> {
        Ok(matches!(self.get(key)?, Some(v @ Value::Str(_)) if v.truthy()))
    }

    /// `_check_is_str(config, key, required=False)`.
    fn is_str_optional(&self, key: &str) -> Result<bool> {
        Ok(matches!(
            self.get(key)?,
            None | Some(Value::None | Value::Str(_))
        ))
    }

    /// `str(config.get(key, "0")).isnumeric()`.
    fn is_numeric_or_missing(&self, key: &str) -> Result<bool> {
        Ok(match self.get(key)? {
            None => true,
            Some(v) => str_isnumeric(&v.py_str()),
        })
    }

    fn truthy(&self, key: &str) -> Result<bool> {
        Ok(self.get(key)?.is_some_and(Value::truthy))
    }

    fn push(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
    }

    fn validate_subconfig(&mut self, key: &str, value: &Value) {
        if let Value::Dict(d) = value {
            for (key2, value2) in d.iter() {
                let subkey = format!("{key}.{}", key2.py_str());
                if !known_keys::is_known_config_key(&subkey) {
                    self.push(messages::unknown_setting_key(&subkey));
                }
                self.validate_subconfig(&subkey, value2);
            }
        }
    }

    fn run(&mut self) -> Result<()> {
        let config = self.config;
        for (key, value) in config.iter() {
            let key = key.py_str();
            if key == "sources" || KNOWN_FLEXIBLE_KEYS.contains(&key.as_str()) {
                continue;
            }
            if !known_keys::is_known_config_key(&key) {
                self.push(messages::unknown_setting_key(&key));
            }
            self.validate_subconfig(&key, value);
        }

        if !self.is_str_required("database_url")? {
            self.push(messages::DATABASE_URL_REQUIRED);
        }
        if !self.is_str_required("redis_url")? {
            self.push(messages::REDIS_URL_REQUIRED);
        }
        let piddir_ok = self.is_str_required("piddir")?
            && match self.get("piddir")? {
                Some(v) => isdir(self.is_dir, v)?,
                None => false,
            };
        if !piddir_ok {
            self.push(messages::PIDDIR_REQUIRED);
        }
        if !self.is_numeric_or_missing("route_object_preference.update_timer")? {
            self.push(messages::ROUTE_OBJECT_PREFERENCE_UPDATE_TIMER);
        }
        if !self.is_numeric_or_missing("download_timeout")? {
            self.push(messages::DOWNLOAD_TIMEOUT);
        }

        let whois_access_list = self.get("server.whois.access_list")?;
        let status_access_list = self.get("server.http.status_access_list")?;
        let mut expected_access_lists = PySet::default();
        expected_access_lists.add(whois_access_list.unwrap_or(&Value::None))?;
        expected_access_lists.add(status_access_list.unwrap_or(&Value::None))?;

        let email_from_ok = self.is_str_required("email.from")?
            && self
                .get("email.from")?
                .and_then(Value::as_str)
                .is_some_and(|s| s.contains('@'));
        if !email_from_ok {
            self.push(messages::EMAIL_FROM);
        }
        if !self.is_str_required("email.smtp")? {
            self.push(messages::EMAIL_SMTP);
        }
        let override_ok = self.is_str_optional("email.recipient_override")? && {
            let haystack = self
                .get("email.recipient_override")?
                .cloned()
                .unwrap_or_else(|| Value::str("@"));
            haystack.py_contains(&Value::str("@"))?
        };
        if !override_ok {
            self.push(messages::EMAIL_RECIPIENT_OVERRIDE);
        }

        let url = urlparse(self.get("server.http.url")?)?;
        if url.scheme.is_empty() || url.netloc.is_empty() {
            self.push(messages::SERVER_HTTP_URL);
        }

        for setting in [
            "email.footer",
            "server.whois.access_list",
            "server.http.status_access_list",
            "rpki.notify_invalid_subject",
            "rpki.notify_invalid_header",
            "rpki.slurm_source",
            "user",
            "group",
        ] {
            if !self.is_str_optional(setting)? {
                self.push(messages::must_be_string_if_defined(setting));
            }
        }

        if self.truthy("user")? != self.truthy("group")? {
            self.push(messages::USER_AND_GROUP);
        }
        if !self.is_str_required("auth.gnupg_keyring")? {
            self.push(messages::GNUPG_KEYRING);
        }
        if !matches!(
            self.get("auth.irrd_internal_migration_enabled")?,
            None | Some(Value::Bool(_))
        ) {
            self.push(messages::IRRD_INTERNAL_MIGRATION_ENABLED);
        }
        if let Some(limit) = self.get("auth.webui_auth_failure_rate_limit")?
            && limit.truthy()
            && !limit.as_str().is_some_and(ratelimit::parses)
        {
            self.push(messages::WEBUI_AUTH_FAILURE_RATE_LIMIT);
        }

        self.check_set_creation()?;
        self.check_password_hashers()?;
        self.check_access_lists()?;
        self.check_scopefilter()?;

        let empty = Dict::new();
        let sources = match self.get("sources")? {
            None => &empty,
            Some(Value::Dict(d)) => d,
            Some(other) => return Err(PyException::attribute_error(other, "keys")),
        };
        let mut known_sources = PySet::default();
        for name in sources.keys() {
            known_sources.add(name)?;
        }
        let mut has_authoritative_sources = false;
        for (name, details) in sources.iter() {
            let name = name.py_str();
            let details = match details {
                Value::Dict(d) => d,
                other => return Err(PyException::attribute_error(other, "keys")),
            };
            self.check_source(
                &name,
                details,
                &mut has_authoritative_sources,
                &mut expected_access_lists,
            )?;
        }

        for key in ["nrtm4_server_local_path"] {
            // collections.Counter over the values, in first-seen order.
            let mut counts: Vec<(Value, usize)> = Vec::new();
            for details in sources.values() {
                let value = details
                    .as_dict()
                    .and_then(|d| d.get_str(key))
                    .cloned()
                    .unwrap_or(Value::None);
                if matches!(value, Value::Dict(_) | Value::Set(_)) {
                    return Err(PyException::unhashable(&value));
                }
                let existing = counts
                    .iter_mut()
                    .find(|(v, _)| !matches!(v, Value::List(_)) && v.py_eq(&value));
                match existing {
                    Some(entry) if !matches!(value, Value::List(_)) => entry.1 += 1,
                    _ => counts.push((value, 1)),
                }
            }
            let duplicates: Vec<Value> = counts
                .into_iter()
                .filter(|(v, c)| v.truthy() && *c > 1)
                .map(|(v, _)| v)
                .collect();
            if !duplicates.is_empty() {
                let joined = join(",", &duplicates)?;
                self.push(messages::duplicate_source_values(&joined, key));
            }
        }

        // config.get("rpki.roa_source", DEFAULT_ROA_SOURCE): the default is truthy.
        let roa_source_enabled = self.get("rpki.roa_source")?.is_none_or(Value::truthy);
        if roa_source_enabled {
            known_sources.add(&Value::str(RPKI_IRR_PSEUDO_SOURCE))?;
            let notify_unset = matches!(
                self.get("rpki.notify_invalid_enabled")?,
                None | Some(Value::None)
            );
            if has_authoritative_sources && notify_unset {
                self.push(messages::RPKI_NOTIFY_INVALID_NOT_SET);
            }
        }

        let aliases = match self.get("source_aliases")? {
            None => &empty,
            Some(v) => items(v)?,
        };
        for (alias_name, aliased_sources) in aliases.iter() {
            let alias = alias_name.py_str();
            if !is_valid_source_name(&alias) {
                self.push(messages::invalid_source_alias_name(&alias));
            }
            if known_sources.contains(alias_name)? {
                self.push(messages::source_alias_conflict(&alias));
            }
            for aliased in aliased_sources.py_iter()? {
                if !known_sources.contains(&aliased)? {
                    self.push(messages::source_alias_unknown_source(
                        &alias,
                        &aliased.py_str(),
                    ));
                }
            }
        }
        for alias_name in aliases.keys() {
            known_sources.add(alias_name)?;
        }

        if let Some(defaults) = self.get("sources_default")? {
            let mut unknown = PySet::default();
            for source in defaults.py_iter()? {
                if !known_sources.contains(&source)? {
                    unknown.add(&source)?;
                }
            }
            if !unknown.items.is_empty() {
                // Python orders this set by string hash, which is randomised
                // per process; irrd-ng keeps the configuration's order.
                let joined = join(", ", &unknown.items)?;
                self.push(messages::sources_default_unknown(&joined));
            }
        }

        if !self.is_numeric_or_missing("rpki.roa_import_timer")? {
            self.push(messages::ROA_IMPORT_TIMER);
        }

        if let Some(level) = self.get("log.level")?
            && level.truthy()
        {
            let valid = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"];
            if !valid.iter().any(|v| level.as_str() == Some(*v)) {
                self.push(messages::invalid_log_level(&level.py_str()));
            }
        }
        if self.truthy("log.logging_config_path")?
            && (self.truthy("log.logfile_path")? || self.truthy("log.level")?)
        {
            self.push(messages::LOGGING_CONFIG_PATH_COMBINED);
        }

        let access_lists = match self.get("access_lists")? {
            None => &empty,
            Some(v) => items(v)?,
        };
        let mut unresolved: Vec<String> = expected_access_lists
            .items
            .iter()
            .filter_map(Value::as_str)
            .filter(|name| !name.is_empty() && access_lists.get_str(name).is_none())
            .map(str::to_owned)
            .collect();
        unresolved.sort();
        if !unresolved.is_empty() {
            self.push(messages::unresolved_access_lists(&unresolved.join(", ")));
        }
        // irrd-ng's own key comes after every check v4 makes, so a
        // v4-valid file gets v4's result and nothing more.
        self.check_ng_replication()
    }

    /// irrd-ng only: `ng_replication`. The secret may also come from the
    /// environment (`IRRD_NG_REPLICATION_SECRET`), so it is only checked
    /// here when the file sets it; the daemon refuses to replicate without
    /// one.
    fn check_ng_replication(&mut self) -> Result<()> {
        let Some(section) = self.get(known_keys::NG_REPLICATION_KEY)? else {
            return Ok(());
        };
        if matches!(section, Value::None) {
            return Ok(());
        }
        if !matches!(section, Value::Dict(_)) {
            self.push(messages::NG_REPLICATION_NOT_MAPPING);
            return Ok(());
        }
        if let Some(secret) = self.get("ng_replication.secret")?
            && !secret.as_str().is_some_and(|s| s.chars().count() >= 16)
        {
            self.push(messages::NG_REPLICATION_SECRET);
        }
        if let Some(interface) = self.get("ng_replication.interface")?
            && !interface
                .as_str()
                .is_some_and(|s| s.parse::<std::net::IpAddr>().is_ok())
        {
            self.push(messages::NG_REPLICATION_INTERFACE);
        }
        for key in ["port", "active_port"] {
            if let Some(port) = self.get(&format!("ng_replication.{key}"))? {
                let ok = str_isnumeric(&port.py_str())
                    && port
                        .py_str()
                        .parse::<u32>()
                        .is_ok_and(|p| (1..=65535).contains(&p));
                if !ok {
                    self.push(messages::ng_replication_port(key));
                }
            }
        }
        if let Some(host) = self.get("ng_replication.active_host")? {
            if !host.as_str().is_some_and(|s| !s.is_empty()) {
                self.push(messages::NG_REPLICATION_ACTIVE_HOST);
            }
            if !self.truthy("readonly_standby")? {
                self.push(messages::NG_REPLICATION_ACTIVE_NEEDS_STANDBY);
            }
            if self.get("ng_replication.active_port")?.is_none() {
                self.push(messages::NG_REPLICATION_ACTIVE_PORT_REQUIRED);
            }
        }
        self.check_ng_replication_tls()
    }

    /// irrd-ng only: the TLS sub-keys of `ng_replication`. The files are
    /// read when the daemon starts, which refuses to start if they are not
    /// usable.
    fn check_ng_replication_tls(&mut self) -> Result<()> {
        let mut present = [false; 3];
        for (i, key) in ["tls_certificate", "tls_key", "tls_ca"]
            .into_iter()
            .enumerate()
        {
            if let Some(v) = self.get(&format!("ng_replication.{key}"))? {
                if !v.as_str().is_some_and(|s| !s.is_empty()) {
                    self.push(messages::ng_replication_path(key));
                }
                present[i] = true;
            }
        }
        let [certificate, key, ca] = present;
        if certificate != key {
            self.push(messages::NG_REPLICATION_TLS_PAIR);
        }
        if let Some(pin) = self.get("ng_replication.tls_pin")? {
            if !pin.as_str().is_some_and(valid_tls_pin) {
                self.push(messages::NG_REPLICATION_TLS_PIN);
            }
            if ca {
                self.push(messages::NG_REPLICATION_TLS_CA_AND_PIN);
            }
        }
        if let Some(name) = self.get("ng_replication.tls_server_name")?
            && !name.as_str().is_some_and(valid_tls_server_name)
        {
            self.push(messages::NG_REPLICATION_TLS_SERVER_NAME);
        }
        Ok(())
    }

    fn check_set_creation(&mut self) -> Result<()> {
        let Some(set_creation) = self.get("auth.set_creation")? else {
            return Ok(());
        };
        let valid_auth = Value::List(
            AUTNUM_AUTHENTICATION_MODES
                .iter()
                .map(|m| Value::str(*m))
                .collect(),
        )
        .py_repr();
        for (set_name, params) in items(set_creation)?.iter() {
            let set_name = set_name.py_str();
            let params = match params {
                Value::Dict(d) => d,
                other => return Err(PyException::attribute_error(other, "get")),
            };
            if !matches!(
                params.get_str("prefix_required"),
                None | Some(Value::Bool(_))
            ) {
                self.push(messages::set_creation_prefix_required(&set_name));
            }
            if let Some(mode) = params.get_str("autnum_authentication")
                && mode.truthy()
            {
                let Value::Str(mode) = mode else {
                    return Err(PyException::attribute_error(mode, "lower"));
                };
                if !AUTNUM_AUTHENTICATION_MODES.contains(&mode.to_lowercase().as_str()) {
                    self.push(messages::set_creation_autnum_authentication(
                        &set_name,
                        &valid_auth,
                    ));
                }
            }
        }
        Ok(())
    }

    fn check_password_hashers(&mut self) -> Result<()> {
        let Some(hashers) = self.get("auth.password_hashers")? else {
            return Ok(());
        };
        let valid = Value::List(
            PASSWORD_HASHER_AVAILABILITY
                .iter()
                .map(|m| Value::str(*m))
                .collect(),
        )
        .py_repr();
        for (hasher_name, setting) in items(hashers)?.iter() {
            let Value::Str(setting) = setting else {
                return Err(PyException::attribute_error(setting, "lower"));
            };
            if !PASSWORD_HASHER_AVAILABILITY.contains(&setting.to_lowercase().as_str()) {
                self.push(messages::password_hasher(&hasher_name.py_str(), &valid));
            }
        }
        Ok(())
    }

    fn check_access_lists(&mut self) -> Result<()> {
        let Some(lists) = self.get("access_lists")? else {
            return Ok(());
        };
        for (name, access_list) in items(lists)?.iter() {
            let name = name.py_str();
            for item in access_list.py_iter()? {
                match ipy::ip(&item) {
                    Ok(_) => {}
                    Err(IpError::Value(ve)) => {
                        self.push(messages::invalid_access_list_item(&name, &ve));
                    }
                    Err(IpError::Crash(e)) => return Err(e),
                }
            }
        }
        Ok(())
    }

    fn check_scopefilter(&mut self) -> Result<()> {
        if let Some(prefixes) = self.get("scopefilter.prefixes")? {
            for prefix in prefixes.py_iter()? {
                match ipy::ip(&prefix) {
                    Ok(_) => {}
                    Err(IpError::Value(ve)) => {
                        self.push(messages::invalid_prefix_scopefilter(&prefix.py_str(), &ve));
                    }
                    Err(IpError::Crash(e)) => return Err(e),
                }
            }
        }
        if let Some(asns) = self.get("scopefilter.asns")? {
            for asn in asns.py_iter()? {
                let shown = asn.py_str();
                let result = if shown.contains('-') {
                    match &asn {
                        Value::Str(s) => {
                            let parts: Vec<&str> = s.split('-').collect();
                            if parts.len() == 2 {
                                crate::python::int_from_str(parts[0], 10)
                                    .and_then(|_| crate::python::int_from_str(parts[1], 10))
                                    .map(|_| ())
                            } else {
                                Err(PyException::value_error("wrong number of values to unpack"))
                            }
                        }
                        other => return Err(PyException::attribute_error(other, "split")),
                    }
                } else {
                    int_of(&asn).map(|_| ())
                };
                match result {
                    Ok(()) => {}
                    Err(e) if e.kind == "ValueError" => {
                        self.push(messages::invalid_asn_scopefilter(&shown));
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    fn check_source(
        &mut self,
        name: &str,
        details: &Dict,
        has_authoritative_sources: &mut bool,
        expected_access_lists: &mut PySet,
    ) -> Result<()> {
        let get = |k: &str| details.get_str(k);
        let truthy = |k: &str| details.get_str(k).is_some_and(Value::truthy);

        let unknown: Vec<String> = details
            .keys()
            .map(Value::py_str)
            .filter(|k| !known_keys::is_known_source_key(k))
            .collect();
        if !unknown.is_empty() {
            // Python builds this from a set, ordered by string hash, which
            // is randomised per process; irrd-ng keeps the configuration's
            // order.
            self.push(messages::unknown_source_keys(name, &unknown.join(", ")));
        }
        if truthy("authoritative") {
            *has_authoritative_sources = true;
        }
        if self.truthy("rpki.roa_source")? && name == RPKI_IRR_PSEUDO_SOURCE {
            self.push(messages::reserved_source_name(RPKI_IRR_PSEUDO_SOURCE));
        }
        if !is_valid_source_name(name) {
            self.push(messages::invalid_source_name(name));
        }
        if truthy("suspension_enabled") && !truthy("authoritative") {
            self.push(messages::suspension_without_authoritative(name));
        }

        let nrtm3_mirror_client = truthy("nrtm_host") && truthy("import_serial_source");
        let unf_url = get("nrtm4_client_notification_file_url");
        let unf_url_set = unf_url.is_some_and(Value::truthy);
        let url = urlparse(unf_url)?;
        if unf_url_set
            && !((url.scheme == "https" && !url.netloc.is_empty())
                || (url.scheme == "file" && !url.path.is_empty()))
        {
            self.push(messages::nrtm4_client_url_invalid(name));
        }
        if truthy("keep_journal")
            && !(nrtm3_mirror_client || unf_url_set || truthy("authoritative"))
        {
            self.push(messages::keep_journal_unsupported(name));
        }
        if truthy("nrtm_host") && !truthy("import_serial_source") {
            self.push(messages::nrtm_host_without_serial_source(name));
        }
        if unf_url_set && !truthy("nrtm4_client_initial_public_key") {
            self.push(messages::nrtm4_client_url_without_key(name));
        }
        if let Some(key) = get("nrtm4_client_initial_public_key")
            && key.truthy()
        {
            self.check_key("nrtm4_client_initial_public_key", name, key, false)?;
        }
        if unf_url_set && (truthy("nrtm_host") || truthy("import_serial_source")) {
            self.push(messages::nrtm3_and_nrtm4_client(name));
        }
        if truthy("authoritative")
            && (unf_url_set || truthy("nrtm_host") || truthy("import_source"))
        {
            self.push(messages::authoritative_with_mirroring(name));
        }

        let nrtm4_server_enabled =
            truthy("nrtm4_server_private_key") || truthy("nrtm4_server_local_path");
        if (nrtm4_server_enabled || truthy("nrtm4_server_private_key_next"))
            && !(truthy("nrtm4_server_private_key") && truthy("nrtm4_server_local_path"))
        {
            self.push(messages::nrtm4_server_incomplete(name));
        }
        if nrtm4_server_enabled && !truthy("keep_journal") {
            self.push(messages::nrtm4_server_requires_keep_journal(name));
        }
        if let Some(key) = get("nrtm4_server_private_key")
            && key.truthy()
        {
            self.check_key("nrtm4_server_private_key", name, key, true)?;
        }
        if let Some(key) = get("nrtm4_server_private_key_next")
            && key.truthy()
        {
            self.check_key("nrtm4_server_private_key_next", name, key, true)?;
        }
        if let Some(path) = get("nrtm4_server_local_path")
            && path.truthy()
            && !isdir(self.is_dir, path)?
        {
            self.push(messages::nrtm4_server_local_path_missing(name));
        }

        let default_frequency = Value::int(DEFAULT_SOURCE_NRTM4_SERVER_SNAPSHOT_FREQUENCY);
        let frequency = get("nrtm4_server_snapshot_frequency").unwrap_or(&default_frequency);
        // 3600.0 <= frequency <= 86400.0, with Python's mixed comparisons.
        let in_range = match frequency {
            Value::Int(i) => *i >= BigInt::from(3600) && *i <= BigInt::from(86400),
            Value::Bool(_) => false,
            Value::Float(f) => (3600.0..=86400.0).contains(f),
            other => {
                return Err(PyException::type_error(format!(
                    "'<=' not supported between instances of 'float' and '{}'",
                    other.type_name()
                )));
            }
        };
        if !in_range {
            self.push(messages::nrtm4_snapshot_frequency(
                name,
                NRTM4_SERVER_DELTA_EXPIRY_SECONDS,
            ));
        }

        if self.truthy("readonly_standby")?
            && (truthy("authoritative")
                || truthy("nrtm_host")
                || truthy("import_source")
                || truthy("export_destination")
                || truthy("export_destination_unfiltered")
                || unf_url_set
                || nrtm4_server_enabled)
        {
            self.push(messages::readonly_standby_source(name));
        }

        for field in [
            "nrtm_port",
            "import_timer",
            "export_timer",
            "route_object_preference",
            "nrtm_query_serial_range_limit",
            "nrtm_query_serial_days_limit",
            "nrtm4_server_snapshot_frequency",
            "nrtm3_client_timeout",
        ] {
            let numeric = match get(field) {
                None => true,
                Some(v) => str_isnumeric(&v.py_str()),
            };
            if !numeric {
                self.push(messages::source_number_field(field, name));
            }
        }

        if let Some(list) = get("nrtm_access_list")
            && list.truthy()
        {
            expected_access_lists.add(list)?;
        }
        if let Some(list) = get("nrtm_access_list_unfiltered")
            && list.truthy()
        {
            expected_access_lists.add(list)?;
        }
        Ok(())
    }

    fn check_key(&mut self, setting: &str, name: &str, key: &Value, private: bool) -> Result<()> {
        match eckey::eckey_from_str(key, private) {
            Ok(()) => Ok(()),
            Err(KeyError::Value(ve)) => {
                self.push(messages::invalid_key_setting(setting, name, &ve));
                Ok(())
            }
            Err(KeyError::Crash(e)) => Err(e),
        }
    }
}

/// Run v4's checks on the `irrd` mapping.
pub(crate) fn check_staging_config(config: &Dict, is_dir: IsDir<'_>) -> Result<Vec<String>> {
    let mut checker = Checker {
        config,
        is_dir,
        errors: Vec::new(),
    };
    checker.run()?;
    Ok(checker.errors)
}

/// 64 hexadecimal digits, optionally separated by single colons.
fn valid_tls_pin(s: &str) -> bool {
    let digits = s.bytes().filter(|b| *b != b':');
    !s.starts_with(':')
        && !s.ends_with(':')
        && !s.contains("::")
        && digits.clone().count() == 64
        && digits.into_iter().all(|b| b.is_ascii_hexdigit())
}

/// An IP address, or a DNS name of ASCII labels.
fn valid_tls_server_name(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
        || (!s.is_empty()
            && s.len() <= 253
            && s.trim_end_matches('.').split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && l.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            }))
}
