//! Tests for the configuration API.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use super::*;

/// A config file in a fresh temporary directory, removed on drop.
struct TempConfig {
    dir: PathBuf,
    path: PathBuf,
}

impl TempConfig {
    fn new(tag: &str, text: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("irrd-ng-config-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("irrd.yaml");
        std::fs::write(&path, text).unwrap();
        TempConfig { dir, path }
    }

    fn path(&self) -> &str {
        self.path.to_str().unwrap()
    }

    fn write(&self, text: &str) {
        std::fs::write(&self.path, text).unwrap();
    }
}

impl Drop for TempConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const VALID: &str = "irrd:
  database_url: postgresql://localhost/irrd
  redis_url: redis://localhost
  piddir: /tmp
  server:
    http:
      url: https://irrd.example.net/
    whois:
      port: 8043
  email:
    from: irrd@example.net
    smtp: localhost
  auth:
    gnupg_keyring: /tmp/gnupg
  rpki:
    roa_source: null
  sources_default: [TEST]
  sources:
    TEST:
      authoritative: true
";

fn no_env(_: &str) -> Option<String> {
    None
}

#[test]
fn load_valid_and_get_settings() {
    let cfg = TempConfig::new("valid", VALID);
    let c = Configuration::load(Some(cfg.path())).unwrap();
    // From the file.
    let port = c
        .get_setting_live_with_env("server.whois.port", no_env)
        .unwrap();
    assert_eq!(port.map(|v| v.py_repr()), Some("8043".to_owned()));
    // An explicit null in the file wins over the default.
    let roa = c
        .get_setting_live_with_env("rpki.roa_source", no_env)
        .unwrap();
    assert!(matches!(roa.as_deref(), Some(Value::None)));
    // From v4's default_config.yaml.
    let interface = c
        .get_setting_live_with_env("server.whois.interface", no_env)
        .unwrap();
    assert_eq!(interface.map(|v| v.py_str()), Some("::0".to_owned()));
    let hasher = c
        .get_setting_live_with_env("auth.password_hashers.crypt-pw", no_env)
        .unwrap();
    assert_eq!(hasher.map(|v| v.py_str()), Some("legacy".to_owned()));
    // Known but unset anywhere: the caller's default applies.
    let logfile = c
        .get_setting_live_with_env("log.logfile_path", no_env)
        .unwrap();
    assert!(logfile.is_none());
    // Per-source settings.
    let auth = c
        .get_setting_live_with_env("sources.TEST.authoritative", no_env)
        .unwrap();
    assert!(matches!(auth.as_deref(), Some(Value::Bool(true))));
}

#[test]
fn environment_overrides_file_and_defaults() {
    let cfg = TempConfig::new("env", VALID);
    let c = Configuration::load(Some(cfg.path())).unwrap();
    let env = |k: &str| match k {
        "IRRD_SERVER_WHOIS_PORT" => Some("4343".to_owned()),
        "IRRD_SERVER_WHOIS_INTERFACE" => Some("env_value".to_owned()),
        "IRRD_SOURCES_TEST_KEEP_JOURNAL" => Some("1".to_owned()),
        _ => None,
    };
    // Env values are always strings, as in v4.
    let port = c
        .get_setting_live_with_env("server.whois.port", env)
        .unwrap();
    assert!(matches!(port.as_deref(), Some(Value::Str(s)) if s == "4343"));
    let interface = c
        .get_setting_live_with_env("server.whois.interface", env)
        .unwrap();
    assert!(matches!(interface.as_deref(), Some(Value::Str(s)) if s == "env_value"));
    let journal = c
        .get_setting_live_with_env("sources.TEST.keep_journal", env)
        .unwrap();
    assert!(matches!(journal.as_deref(), Some(Value::Str(s)) if s == "1"));
}

#[test]
fn unknown_settings_are_refused() {
    let cfg = TempConfig::new("unknown", VALID);
    let c = Configuration::load(Some(cfg.path())).unwrap();
    for name in ["unknown", "log.unknown", "sources.TEST.unknown"] {
        assert_eq!(
            c.get_setting_live_with_env(name, no_env)
                .unwrap_err()
                .to_string(),
            format!("Unknown setting {name}")
        );
    }
    // v4 only checks the third component of sources.* names, and any name
    // starting with a flexible key or "sources" passes.
    assert!(
        c.get_setting_live_with_env("sources_default", no_env)
            .is_ok()
    );
    assert!(c.get_setting_live_with_env("sources.TEST", no_env).is_ok());
    assert!(
        c.get_setting_live_with_env("access_lists.anything", no_env)
            .is_ok()
    );
    assert!(c.get_setting_live_with_env("server", no_env).is_ok());
}

#[test]
fn startup_failure_message_matches_v4() {
    let cfg = TempConfig::new("invalid", "irrd:\n  log:\n    level: it's\n");
    let err = Configuration::load(Some(cfg.path())).unwrap_err();
    let text = err.to_string();
    assert!(text.starts_with(
        "Errors found in configuration, unable to start: ['Setting database_url is required.', "
    ));
    assert!(text.ends_with(
        "\"Invalid log.level: it's. Valid settings for log.level are `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`.\"]"
    ));
}

#[test]
fn missing_file() {
    let err = Configuration::load(Some("/nonexistent-irrd-ng/irrd.yaml")).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Errors found in configuration, unable to start: [\"Error opening config file \
         /nonexistent-irrd-ng/irrd.yaml: [Errno 2] No such file or directory: \
         '/nonexistent-irrd-ng/irrd.yaml'\"]"
    );
}

#[test]
fn crash_is_reported_not_panicked() {
    let cfg = TempConfig::new("crash", "irrd:\n  sources:\n");
    let err = Configuration::load(Some(cfg.path())).unwrap_err();
    assert!(matches!(&err, ConfigError::Crash(e) if e.kind == "AttributeError"));
    assert_eq!(
        err.to_string(),
        "Errors found in configuration, unable to start: unexpected AttributeError: \
         'NoneType' object has no attribute 'keys'"
    );
}

#[test]
fn reload_keeps_settings_on_error() {
    let cfg = TempConfig::new("reload", VALID);
    let mut c = Configuration::load(Some(cfg.path())).unwrap();
    cfg.write(&VALID.replace("port: 8043", "port: 8044"));
    c.reload().unwrap();
    let port = c
        .get_setting_live_with_env("server.whois.port", no_env)
        .unwrap();
    assert_eq!(port.map(|v| v.py_repr()), Some("8044".to_owned()));
    cfg.write("irrd: {}\n");
    assert!(matches!(c.reload(), Err(ConfigError::Invalid { .. })));
    let port = c
        .get_setting_live_with_env("server.whois.port", no_env)
        .unwrap();
    assert_eq!(port.map(|v| v.py_repr()), Some("8044".to_owned()));
}

#[test]
fn storage_notice() {
    let cfg = TempConfig::new("notice", VALID);
    let c = Configuration::load(Some(cfg.path())).unwrap();
    assert_eq!(
        c.storage_notice().as_deref(),
        Some(
            "Settings database_url, redis_url are accepted for compatibility with IRRd v4 and \
             ignored: irrd-ng uses its embedded store."
        )
    );
}

#[test]
fn every_known_key_has_a_reload_class() {
    let cfg = TempConfig::new("reload-class", VALID);
    let c = Configuration::load(Some(cfg.path())).unwrap();
    for spec in KEY_SPECS {
        let concrete = spec
            .key
            .replace("{name}", "TEST")
            .replace("{list_name}", "list")
            .replace("{set_class}", "as-set")
            .replace("{hasher}", "md5-pw");
        assert!(
            c.get_setting_live_with_env(&concrete, no_env).is_ok(),
            "{concrete} is in KEY_SPECS but not a known setting"
        );
        assert_eq!(spec_for(&concrete).map(|s| s.key), Some(spec.key));
    }
}
