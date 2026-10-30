//! User-facing strings, copied verbatim from IRRd v4 at the pinned baseline.
//!
//! Every message a client, operator or mail recipient can see lives here, so a
//! parity fix to wording touches exactly one place. Unless noted, the source is
//! `irrd/conf/__init__.py` at v4.5.4.

// Loading (`_staging_reload_check`, `__init__`, `reload`).

pub(crate) fn error_opening(path: &str, os_error: &str) -> String {
    format!("Error opening config file {path}: {os_error}")
}

pub(crate) fn error_parsing_yaml(yaml_error: &str) -> String {
    format!("Error parsing YAML file: {yaml_error}")
}

pub(crate) fn no_root_item(path: &str) -> String {
    format!("Could not find root item \"irrd\" in config file {path}")
}

/// `ConfigurationError` text at startup; `errors_repr` is the list `repr()`.
pub fn unable_to_start(errors_repr: &str) -> String {
    format!("Errors found in configuration, unable to start: {errors_repr}")
}

/// Logged when a SIGHUP reload is rejected.
pub(crate) fn continuing_with_current(errors_repr: &str) -> String {
    format!("Errors found in configuration, continuing with current settings: {errors_repr}")
}

/// Logged after a successful SIGHUP reload.
pub(crate) fn reloaded(path: &str, pid: u32) -> String {
    format!("Configuration successfully (re)loaded from {path} in PID {pid}")
}

/// `get_setting_live` on a name that is not a known setting.
pub(crate) fn unknown_setting(name: &str) -> String {
    format!("Unknown setting {name}")
}

// `_check_staging_config`, in check order.

pub(crate) fn unknown_setting_key(key: &str) -> String {
    format!("Unknown setting key: {key}")
}

pub(crate) const DATABASE_URL_REQUIRED: &str = "Setting database_url is required.";
pub(crate) const REDIS_URL_REQUIRED: &str = "Setting redis_url is required.";
pub(crate) const PIDDIR_REQUIRED: &str =
    "Setting piddir is required and must point to an existing directory.";
pub(crate) const ROUTE_OBJECT_PREFERENCE_UPDATE_TIMER: &str =
    "Setting route_object_preference.update_timer must be a number.";
pub(crate) const DOWNLOAD_TIMEOUT: &str = "Setting download_timeout must be a number.";
pub(crate) const EMAIL_FROM: &str = "Setting email.from is required and must be an email address.";
pub(crate) const EMAIL_SMTP: &str = "Setting email.smtp is required.";
pub(crate) const EMAIL_RECIPIENT_OVERRIDE: &str =
    "Setting email.recipient_override must be an email address if set.";
pub(crate) const SERVER_HTTP_URL: &str = "Setting server.http.url is missing or invalid.";

pub(crate) fn must_be_string_if_defined(setting: &str) -> String {
    format!("Setting {setting} must be a string, if defined.")
}

pub(crate) const USER_AND_GROUP: &str = "Settings user and group must both be defined, or neither.";
pub(crate) const GNUPG_KEYRING: &str = "Setting auth.gnupg_keyring is required.";
pub(crate) const IRRD_INTERNAL_MIGRATION_ENABLED: &str =
    "Setting auth.irrd_internal_migration_enabled must be a bool.";
pub(crate) const WEBUI_AUTH_FAILURE_RATE_LIMIT: &str =
    "Setting auth.webui_auth_failure_rate_limit is missing or invalid.";

pub(crate) fn set_creation_prefix_required(set_name: &str) -> String {
    format!("Setting auth.set_creation.{set_name}.prefix_required must be a bool")
}

pub(crate) fn set_creation_autnum_authentication(set_name: &str, valid_repr: &str) -> String {
    format!(
        "Setting auth.set_creation.{set_name}.autnum_authentication must be one of {valid_repr} if set"
    )
}

pub(crate) fn password_hasher(hasher_name: &str, valid_repr: &str) -> String {
    format!("Setting auth.password_hashers.{hasher_name} must be one of {valid_repr}")
}

pub(crate) fn invalid_access_list_item(name: &str, error: &str) -> String {
    format!("Invalid item in access list {name}: {error}.")
}

pub(crate) fn invalid_prefix_scopefilter(prefix: &str, error: &str) -> String {
    format!("Invalid item in prefix scopefilter: {prefix}: {error}.")
}

pub(crate) fn invalid_asn_scopefilter(asn: &str) -> String {
    format!("Invalid item in asn scopefilter: {asn}.")
}

pub(crate) fn unknown_source_keys(name: &str, keys: &str) -> String {
    format!("Unknown key(s) under source {name}: {keys}")
}

pub(crate) fn reserved_source_name(name: &str) -> String {
    format!("Setting sources contains reserved source name: {name}")
}

pub(crate) fn invalid_source_name(name: &str) -> String {
    format!("Invalid source name: {name}")
}

pub(crate) fn suspension_without_authoritative(name: &str) -> String {
    format!(
        "Setting suspension_enabled for source {name} can not be enabled without enabling authoritative."
    )
}

pub(crate) fn nrtm4_client_url_invalid(name: &str) -> String {
    format!(
        "Setting nrtm4_client_notification_file_url for source {name} is not a valid https or file URL."
    )
}

pub(crate) fn keep_journal_unsupported(name: &str) -> String {
    format!(
        "Setting keep_journal for source {name} can not be enabled unless either authoritative is enabled, or all three of nrtm_host/nrtm_port/import_serial_source, or nrtm4_client_notification_file_url."
    )
}

pub(crate) fn nrtm_host_without_serial_source(name: &str) -> String {
    format!(
        "Setting nrtm_host for source {name} can not be enabled without setting import_serial_source."
    )
}

pub(crate) fn nrtm4_client_url_without_key(name: &str) -> String {
    format!(
        "Setting nrtm4_client_notification_file_url for source {name} must be set together with nrtm4_client_initial_public_key."
    )
}

pub(crate) fn invalid_key_setting(setting: &str, name: &str, error: &str) -> String {
    format!("Invalid value for setting {setting} for source {name}: {error}")
}

pub(crate) fn nrtm3_and_nrtm4_client(name: &str) -> String {
    format!(
        "Settings nrtm_host/import_serial_source for {name} can not both be set together with nrtm4_client_notification_file_url."
    )
}

pub(crate) fn authoritative_with_mirroring(name: &str) -> String {
    format!(
        "Setting authoritative for source {name} can not be enabled when either nrtm_host, import_source, or nrtm4_client_notification_file_url are set."
    )
}

pub(crate) fn nrtm4_server_incomplete(name: &str) -> String {
    format!(
        "When setting any nrtm4_server setting, all of nrtm4_server_private_key/nrtm4_server_local_path must be set for source {name}."
    )
}

/// DIV-001 (`docs/divergences.md`). v4 4.5.4 prints, literally,
/// `NRTMv4 server requires keep_journal to be set for for source {name}.`:
/// the f-string prefix is missing and "for" is doubled. irrd-ng names the
/// source.
pub(crate) fn nrtm4_server_requires_keep_journal(name: &str) -> String {
    format!("NRTMv4 server requires keep_journal to be set for source {name}.")
}

/// v4's literal text for DIV-001, kept for the parity test and docs.
pub const V4_NRTM4_SERVER_REQUIRES_KEEP_JOURNAL: &str =
    "NRTMv4 server requires keep_journal to be set for for source {name}.";

pub(crate) fn nrtm4_server_local_path_missing(name: &str) -> String {
    format!(
        "Setting nrtm4_server_local_path for source {name} is required and must point to an existing directory."
    )
}

pub(crate) fn nrtm4_snapshot_frequency(name: &str, expiry_seconds: u64) -> String {
    format!(
        "nrtm4_server_snapshot_frequency for source {name} must be between 1 and 24 hours of {expiry_seconds} seconds"
    )
}

pub(crate) fn readonly_standby_source(name: &str) -> String {
    format!(
        "Source {name} can not have authoritative, import_source, nrtm_host, or NRTMv4 client or server set when readonly_standby is enabled."
    )
}

pub(crate) fn source_number_field(field: &str, name: &str) -> String {
    format!("Setting {field} for source {name} must be a number.")
}

pub(crate) fn duplicate_source_values(values: &str, key: &str) -> String {
    format!("Duplicate value(s) {values} for source setting {key}.")
}

/// DIV-002 (`docs/divergences.md`). v4 concatenates two literals without a
/// space, printing `...Set to true or false.DANGER: ...`.
pub(crate) const RPKI_NOTIFY_INVALID_NOT_SET: &str = "RPKI-aware mode is enabled and authoritative sources are configured, but rpki.notify_invalid_enabled is not set. Set to true or false. DANGER: care is required with this setting in testing setups with live data, as it may send bulk emails to real resource contacts unless email.recipient_override is also set. Read documentation carefully.";

/// v4's literal text for DIV-002, kept for the parity test and docs.
pub const V4_RPKI_NOTIFY_INVALID_NOT_SET: &str = "RPKI-aware mode is enabled and authoritative sources are configured, but rpki.notify_invalid_enabled is not set. Set to true or false.DANGER: care is required with this setting in testing setups with live data, as it may send bulk emails to real resource contacts unless email.recipient_override is also set. Read documentation carefully.";

pub(crate) fn invalid_source_alias_name(name: &str) -> String {
    format!("Invalid source alias name: {name}")
}

pub(crate) fn source_alias_conflict(name: &str) -> String {
    format!("Source alias name {name} conflicts with an already configured real source.")
}

pub(crate) fn source_alias_unknown_source(alias: &str, source: &str) -> String {
    format!("Source alias {alias} contains reference to unknown source {source}.")
}

pub(crate) fn sources_default_unknown(sources: &str) -> String {
    format!("Setting sources_default contains unknown sources: {sources}")
}

pub(crate) const ROA_IMPORT_TIMER: &str = "Setting rpki.roa_import_timer must be set to a number.";

pub(crate) fn invalid_log_level(level: &str) -> String {
    format!(
        "Invalid log.level: {level}. Valid settings for log.level are `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`."
    )
}

/// The missing space after "with" is v4's.
pub(crate) const LOGGING_CONFIG_PATH_COMBINED: &str =
    "Setting log.logging_config_path can not be combined withlog.logfile_path or log.level";

pub(crate) fn unresolved_access_lists(names: &str) -> String {
    format!("Access lists {names} referenced in settings, but not defined.")
}

// `irrd/utils/crypto.py`.

pub(crate) const ECKEY_PUBLIC_NOT_PRIVATE: &str =
    "ECKey is a public key, but must be a private key";

// irrd-ng only.

/// Startup failure where v4 would crash with a traceback instead of
/// reporting an error. Not in v4.
pub(crate) fn unable_to_start_crash(exception: &str) -> String {
    format!("Errors found in configuration, unable to start: unexpected {exception}")
}

/// Rejected SIGHUP reload where v4 would crash instead. Not in v4.
pub(crate) fn continuing_with_current_crash(exception: &str) -> String {
    format!(
        "Errors found in configuration, continuing with current settings: unexpected {exception}"
    )
}

/// Logged once at startup when v4's database keys are present.
pub(crate) fn storage_keys_ignored(keys: &str) -> String {
    format!(
        "Settings {keys} are accepted for compatibility with IRRd v4 and ignored: irrd-ng uses its embedded store."
    )
}

/// `getattr(PasswordHasherAvailability, setting.upper())` on a value that
/// is not a member, as `irrd/rpsl/auth.py` raises it.
pub(crate) fn no_hasher_availability(name: &str) -> String {
    format!(
        "type object 'PasswordHasherAvailability' has no attribute {}",
        crate::str_repr(name)
    )
}

/// `setting.upper()` in `irrd/rpsl/auth.py` on a value that is not a string.
pub(crate) fn no_upper(type_name: &str) -> String {
    format!("'{type_name}' object has no attribute 'upper'")
}
