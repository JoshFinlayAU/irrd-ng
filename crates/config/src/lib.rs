//! The irrd.yaml model and its validation.
//!
//! irrd-ng reads the same `irrd.yaml` as IRRd v4 and must accept, reject and
//! report on it exactly as v4 4.5.4 does: the same keys, defaults, error
//! strings in the same order, unknown-key handling and the startup message
//! that embeds the Python `repr()` of the error list. To get there the file
//! goes through a port of PyYAML's safe loader (`yaml`), v4's `DottedDict`
//! (`dotted`) and v4's `_check_staging_config` (`check`), with the
//! library calls v4 makes along the way (IPy, `limits`, `urlparse`,
//! joserfc/cryptography) reproduced in their own modules.
//!
//! `database_url` and `redis_url` are still required, as in v4, and then
//! ignored; [`Configuration::load`] logs a single notice saying so.
//!
//! Each known setting carries when a change takes effect ([`KEY_SPECS`]),
//! for the SIGHUP handling in later phases.

use std::borrow::Cow;

mod check;
mod dotted;
mod eckey;
mod ipy;
mod known_keys;
pub mod messages;
mod python;
mod ratelimit;
mod urlparse;
mod yaml;

pub use known_keys::{
    AUTH_SET_CREATION_COMMON_KEY, KEY_SPECS, KNOWN_FLEXIBLE_KEYS, KNOWN_SOURCES_KEYS, KeySpec,
    PASSWORD_HASHERS, RPSL_SET_CLASSES, Reload, STORAGE_KEYS, spec_for,
};
pub use python::{DateTime, Dict, PyException, Value, str_list_repr, str_repr};

/// v4's `CONFIG_PATH_DEFAULT`.
pub const CONFIG_PATH_DEFAULT: &str = "/etc/irrd.yaml";

/// Why a configuration was not accepted.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// v4's `ConfigurationError`: the checks returned errors. `Display` is
    /// v4's startup message, byte for byte.
    #[error("{}", messages::unable_to_start(&str_list_repr(.errors)))]
    Invalid { errors: Vec<String> },
    /// v4 would have crashed with this Python exception rather than report
    /// an error. irrd-ng refuses the configuration instead.
    #[error("{}", messages::unable_to_start_crash(&.0.to_string()))]
    Crash(PyException),
}

/// The outcome of `_staging_reload_check`.
#[derive(Debug)]
pub enum Staging {
    /// The configuration passed; this is its `irrd` mapping.
    Valid(Dict),
    /// The errors v4 would return, in v4's order.
    Invalid(Vec<String>),
}

impl Staging {
    /// The error list, empty when valid.
    pub fn errors(&self) -> &[String] {
        match self {
            Staging::Valid(_) => &[],
            Staging::Invalid(errors) => errors,
        }
    }
}

/// CPython's `str(OSError)` for a failed `open()`/`read()`.
fn os_error_text(path: &str, e: &std::io::Error) -> String {
    let Some(code) = e.raw_os_error() else {
        return e.to_string();
    };
    let text = e.to_string();
    let strerror = text
        .strip_suffix(&format!(" (os error {code})"))
        .unwrap_or(&text);
    format!("[Errno {code}] {strerror}: {}", str_repr(path))
}

/// What `open(path).read()` in text mode returns: UTF-8 decoded, with
/// universal newlines translated.
fn decode_text(bytes: &[u8]) -> Result<String, PyException> {
    let text = std::str::from_utf8(bytes).map_err(|e| {
        let start = e.valid_up_to();
        let rest = &bytes[start..];
        PyException::new(
            "UnicodeDecodeError",
            format!(
                "'utf-8' codec can't decode byte 0x{:02x} in position {start}: {}",
                rest.first().copied().unwrap_or(0),
                yaml_utf8_reason(rest)
            ),
        )
    })?;
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}

fn yaml_utf8_reason(bytes: &[u8]) -> &'static str {
    yaml::utf8_error_reason(bytes)
}

/// `_staging_reload_check` on the result of reading a configuration file.
///
/// `path` is the name v4 would have opened, which appears in some errors;
/// `contents` is the result of reading it.
pub fn check_source(
    path: &str,
    contents: std::io::Result<Vec<u8>>,
) -> Result<Staging, PyException> {
    check_source_with_fs(path, contents, &check::real_is_dir)
}

/// [`check_source`], with `os.path.isdir` answered by `is_dir`, so a test
/// can evaluate a file against the filesystem v4 saw.
pub fn check_source_with_fs(
    path: &str,
    contents: std::io::Result<Vec<u8>>,
    is_dir: &dyn Fn(&str) -> bool,
) -> Result<Staging, PyException> {
    let bytes = match contents {
        Ok(b) => b,
        Err(e) => {
            return Ok(Staging::Invalid(vec![messages::error_opening(
                path,
                &os_error_text(path, &e),
            )]));
        }
    };
    let text = decode_text(&bytes)?;
    let document = match yaml::safe_load(path, &text) {
        Ok(v) => v,
        Err(yaml::LoadError::Yaml(e)) => {
            return Ok(Staging::Invalid(vec![messages::error_parsing_yaml(&e)]));
        }
        Err(yaml::LoadError::Crash(e)) => return Err(e),
    };
    let root = match &document {
        Value::Dict(d) => d.get(&Value::str("irrd")),
        _ => None,
    };
    let Some(root) = root else {
        return Ok(Staging::Invalid(vec![messages::no_root_item(path)]));
    };
    let config = dotted::dotted_dict_from(root)?;
    let errors = check::check_staging_config(&config, is_dir)?;
    if errors.is_empty() {
        Ok(Staging::Valid(config))
    } else {
        Ok(Staging::Invalid(errors))
    }
}

/// `_staging_reload_check` on the file at `path`.
pub fn staging_reload_check(path: &str) -> Result<Staging, PyException> {
    check_source(path, std::fs::read(path))
}

#[allow(clippy::expect_used)]
static DEFAULT_CONFIG: std::sync::LazyLock<Dict> = std::sync::LazyLock::new(|| {
    let text = include_str!("default_config.yaml");
    let document =
        yaml::safe_load("default_config.yaml", text).expect("v4's default_config.yaml parses");
    let root = document
        .as_dict()
        .and_then(|d| d.get_str("irrd"))
        .expect("default_config.yaml has an irrd root");
    dotted::dotted_dict_from(root).expect("default_config.yaml is a valid DottedDict")
});

/// A setting name `get_setting_live` refuses.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{}", messages::unknown_setting(.0))]
pub struct UnknownSetting(pub String);

/// The loaded configuration, as v4's `Configuration` holds it.
#[derive(Debug)]
pub struct Configuration {
    path: String,
    live: Dict,
}

impl Configuration {
    /// `Configuration(path)`: read and check the file, failing as v4 fails at
    /// startup. `None` uses [`CONFIG_PATH_DEFAULT`].
    pub fn load(path: Option<&str>) -> Result<Self, ConfigError> {
        let path = path.unwrap_or(CONFIG_PATH_DEFAULT).to_owned();
        let live = match staging_reload_check(&path) {
            Ok(Staging::Valid(config)) => config,
            Ok(Staging::Invalid(errors)) => return Err(ConfigError::Invalid { errors }),
            Err(e) => return Err(ConfigError::Crash(e)),
        };
        let configuration = Configuration { path, live };
        if let Some(notice) = configuration.storage_notice() {
            tracing::info!("{notice}");
        }
        Ok(configuration)
    }

    /// The path the configuration was read from.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// `reload()` on SIGHUP: re-read and re-check the file, keeping the
    /// current settings (and logging v4's message) when it fails.
    pub fn reload(&mut self) -> Result<(), ConfigError> {
        match staging_reload_check(&self.path) {
            Ok(Staging::Valid(config)) => {
                self.live = config;
                tracing::info!("{}", messages::reloaded(&self.path, std::process::id()));
                Ok(())
            }
            Ok(Staging::Invalid(errors)) => {
                tracing::error!(
                    "{}",
                    messages::continuing_with_current(&str_list_repr(&errors))
                );
                Err(ConfigError::Invalid { errors })
            }
            Err(e) => {
                tracing::error!(
                    "{}",
                    messages::continuing_with_current_crash(&e.to_string())
                );
                Err(ConfigError::Crash(e))
            }
        }
    }

    /// The one startup notice about v4 storage settings irrd-ng ignores.
    pub fn storage_notice(&self) -> Option<String> {
        let present: Vec<&str> = STORAGE_KEYS
            .iter()
            .copied()
            .filter(|k| self.live.get_str(k).is_some())
            .collect();
        (!present.is_empty()).then(|| messages::storage_keys_ignored(&present.join(", ")))
    }

    /// `get_setting_live(name)`: the environment (`IRRD_` plus the name
    /// upper-cased with dots as underscores), then the configuration file,
    /// then v4's defaults. `Ok(None)` where v4 returns the caller's default.
    pub fn get_setting_live(&self, name: &str) -> Result<Option<Cow<'_, Value>>, UnknownSetting> {
        self.get_setting_live_with_env(name, |k| std::env::var(k).ok())
    }

    /// [`Self::get_setting_live`] with the environment supplied by the caller.
    pub fn get_setting_live_with_env(
        &self,
        name: &str,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Cow<'_, Value>>, UnknownSetting> {
        if name.starts_with("sources") {
            let components: Vec<&str> = name.split('.').collect();
            if components.len() == 3 && !known_keys::is_known_source_key(components[2]) {
                return Err(UnknownSetting(name.to_owned()));
            }
        } else if !KNOWN_FLEXIBLE_KEYS.iter().any(|k| name.starts_with(k))
            && !known_keys::is_known_config_key(name)
        {
            return Err(UnknownSetting(name.to_owned()));
        }
        let env_key = format!("IRRD_{}", name.to_uppercase().replace('.', "_"));
        if let Some(value) = env(&env_key) {
            return Ok(Some(Cow::Owned(Value::Str(value))));
        }
        if let Ok(Some(value)) = dotted::get(&self.live, name) {
            return Ok(Some(Cow::Borrowed(value)));
        }
        Ok(dotted::get(&DEFAULT_CONFIG, name)
            .ok()
            .flatten()
            .map(Cow::Borrowed))
    }

    /// The checked `irrd` mapping as loaded from the file.
    pub fn user_config(&self) -> &Dict {
        &self.live
    }
}

/// Hooks for differential tests against PyYAML. Not part of the API.
#[doc(hidden)]
pub mod __private {
    /// `yaml.safe_load(open(name))` on `bytes`: `OK <repr>` of the document,
    /// `ERR <str(YAMLError)>`, or `CRASH <Exception: message>`.
    pub fn yaml_load_repr(name: &str, bytes: &[u8]) -> String {
        let text = match super::decode_text(bytes) {
            Ok(t) => t,
            Err(e) => return format!("CRASH {e}"),
        };
        match super::yaml::safe_load(name, &text) {
            Ok(v) => format!("OK {}", v.py_repr()),
            Err(super::yaml::LoadError::Yaml(e)) => format!("ERR {e}"),
            Err(super::yaml::LoadError::Crash(e)) => format!("CRASH {e}"),
        }
    }
}

#[cfg(test)]
mod tests;
