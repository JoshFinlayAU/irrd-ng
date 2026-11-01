//! The settings v4 knows (`irrd/conf/known_keys.py`) and when a change to
//! each takes effect (`docs/admins/configuration.rst`, "Change takes
//! effect").

use std::collections::HashSet;
use std::sync::LazyLock;

/// RPSL set classes, from `OBJECT_CLASS_MAPPING` entries that subclass
/// `RPSLSet` in v4. Must match the set classes in the `rpsl` crate.
pub const RPSL_SET_CLASSES: &[&str] = &[
    "as-set",
    "filter-set",
    "peering-set",
    "route-set",
    "rtr-set",
];

/// `AUTH_SET_CREATION_COMMON_KEY`.
pub const AUTH_SET_CREATION_COMMON_KEY: &str = "COMMON";

/// `PASSWORD_HASHERS_ALL` keys, lowercased as `known_keys.py` does.
pub const PASSWORD_HASHERS: &[&str] = &["crypt-pw", "md5-pw", "bcrypt-pw"];

/// `RPSLSetAutnumAuthenticationMode` values, in definition order.
pub(crate) const AUTNUM_AUTHENTICATION_MODES: &[&str] = &["disabled", "opportunistic", "required"];

/// `PasswordHasherAvailability` values, in definition order.
pub(crate) const PASSWORD_HASHER_AVAILABILITY: &[&str] = &["enabled", "legacy", "disabled"];

/// `KNOWN_FLEXIBLE_KEYS`: top-level keys whose children are user-named.
pub const KNOWN_FLEXIBLE_KEYS: &[&str] = &["access_lists", "source_aliases"];

/// `KNOWN_SOURCES_KEYS`, in the order `known_keys.py` lists them.
pub const KNOWN_SOURCES_KEYS: &[&str] = &[
    "authoritative",
    "authoritative_non_strict_mode_dangerous",
    "keep_journal",
    "nrtm_host",
    "nrtm_port",
    "import_source",
    "import_serial_source",
    "import_timer",
    "object_class_filter",
    "export_destination",
    "export_destination_unfiltered",
    "export_timer",
    "nrtm_access_list",
    "nrtm_access_list_unfiltered",
    "nrtm_query_serial_days_limit",
    "nrtm_query_serial_range_limit",
    "nrtm_response_header",
    "nrtm_dummified_attributes",
    "nrtm_dummified_object_classes",
    "nrtm_dummified_remarks",
    "nrtm4_client_notification_file_url",
    "nrtm4_client_initial_public_key",
    "nrtm4_server_private_key",
    "nrtm4_server_private_key_next",
    "nrtm4_server_local_path",
    "nrtm4_server_snapshot_frequency",
    "strict_import_keycert_objects",
    "rpki_excluded",
    "scopefilter_excluded",
    "suspension_enabled",
    "route_object_preference",
    "authoritative_retain_last_modified",
    "nrtm3_client_timeout",
];

/// Settings v4 requires but irrd-ng does not use: it has no PostgreSQL or
/// Redis.
pub const STORAGE_KEYS: &[&str] = &["database_url", "redis_url"];

/// When a changed setting takes effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reload {
    /// Only after a full restart.
    Restart,
    /// After a SIGHUP reload.
    Sighup,
    /// After a SIGHUP reload, once the value is next used, e.g. on the next
    /// update attempt or the next ROA import.
    NextUse,
}

/// One setting, or a family of user-named settings such as
/// `sources.{name}.keep_journal`.
#[derive(Clone, Copy, Debug)]
pub struct KeySpec {
    /// The dotted name, with `{name}`, `{list_name}`, `{set_class}` or
    /// `{hasher}` for user-chosen or enumerated components.
    pub key: &'static str,
    pub reload: Reload,
    /// v4's documented "Change takes effect" text.
    pub takes_effect: &'static str,
}

const fn spec(key: &'static str, reload: Reload, takes_effect: &'static str) -> KeySpec {
    KeySpec {
        key,
        reload,
        takes_effect,
    }
}

const RESTART: &str = "after full IRRd restart.";
const SIGHUP: &str = "after SIGHUP.";
const EMAILS: &str = "after SIGHUP, for all subsequent emails.";
const UPDATE: &str = "upon the next update attempt.";
const QUERIES: &str = "after SIGHUP, for all subsequent queries.";
const MIRROR: &str = "after SIGHUP, at the next mirror update.";
const REQUEST: &str = "after SIGHUP, upon next request.";
const CHANGES: &str = "after SIGHUP, for all subsequent changes.";
const SCOPEFILTER: &str =
    "after SIGHUP. Updating the status of existing objects may take 10-15 minutes.";

/// Every setting v4 accepts, with when a change takes effect.
pub const KEY_SPECS: &[KeySpec] = &[
    spec("database_url", Reload::Restart, RESTART),
    spec("readonly_standby", Reload::Restart, RESTART),
    spec("redis_url", Reload::Restart, RESTART),
    spec("piddir", Reload::Restart, RESTART),
    spec("user", Reload::Restart, RESTART),
    spec("group", Reload::Restart, RESTART),
    spec("download_timeout", Reload::Restart, RESTART),
    spec("server.http.interface", Reload::Restart, RESTART),
    spec("server.http.port", Reload::Restart, RESTART),
    spec("server.http.status_access_list", Reload::Sighup, SIGHUP),
    spec(
        "server.http.event_stream_access_list",
        Reload::Sighup,
        SIGHUP,
    ),
    spec("server.http.workers", Reload::Restart, RESTART),
    spec(
        "server.http.forwarded_allowed_ips",
        Reload::Restart,
        RESTART,
    ),
    spec("server.http.url", Reload::Sighup, SIGHUP),
    spec("server.whois.interface", Reload::Restart, RESTART),
    spec("server.whois.port", Reload::Restart, RESTART),
    spec("server.whois.access_list", Reload::Sighup, SIGHUP),
    spec("server.whois.max_connections", Reload::Restart, RESTART),
    spec(
        "route_object_preference.update_timer",
        Reload::Sighup,
        SIGHUP,
    ),
    spec("email.from", Reload::Sighup, EMAILS),
    spec("email.footer", Reload::Sighup, EMAILS),
    spec("email.smtp", Reload::Sighup, EMAILS),
    spec("email.recipient_override", Reload::Sighup, EMAILS),
    spec("email.notification_header", Reload::Sighup, EMAILS),
    spec("auth.override_password", Reload::NextUse, UPDATE),
    spec(
        "auth.authenticate_parents_route_creation",
        Reload::NextUse,
        UPDATE,
    ),
    spec("auth.gnupg_keyring", Reload::Restart, RESTART),
    spec(
        "auth.irrd_internal_migration_enabled",
        Reload::Sighup,
        "after SIGHUP, for all subsequent attempts to initiate a migration.",
    ),
    spec(
        "auth.webui_auth_failure_rate_limit",
        Reload::Restart,
        RESTART,
    ),
    spec(
        "auth.set_creation.{set_class}.prefix_required",
        Reload::NextUse,
        UPDATE,
    ),
    spec(
        "auth.set_creation.{set_class}.autnum_authentication",
        Reload::NextUse,
        UPDATE,
    ),
    spec("auth.password_hashers.{hasher}", Reload::NextUse, UPDATE),
    spec(
        "access_lists.{list_name}",
        Reload::Sighup,
        "after SIGHUP, for all subsequent requests.",
    ),
    spec(
        "rpki.roa_source",
        Reload::Sighup,
        "after SIGHUP. The first RPKI ROA import may take several minutes, after which RPKI-aware mode is enabled.",
    ),
    spec("rpki.roa_import_timer", Reload::Sighup, SIGHUP),
    spec(
        "rpki.slurm_source",
        Reload::Sighup,
        "after SIGHUP, upon next full ROA import.",
    ),
    spec(
        "rpki.pseudo_irr_remarks",
        Reload::NextUse,
        "after the next ROA import.",
    ),
    spec(
        "rpki.notify_invalid_enabled",
        Reload::NextUse,
        "the next time an authoritative route(6) object is newly marked RPKI invalid.",
    ),
    spec(
        "rpki.notify_invalid_subject",
        Reload::NextUse,
        "after the next ROA import.",
    ),
    spec(
        "rpki.notify_invalid_header",
        Reload::NextUse,
        "after the next ROA import.",
    ),
    spec("scopefilter.prefixes", Reload::Sighup, SCOPEFILTER),
    spec("scopefilter.asns", Reload::Sighup, SCOPEFILTER),
    spec("log.logfile_path", Reload::Restart, RESTART),
    spec("log.level", Reload::Sighup, SIGHUP),
    spec("log.logging_config_path", Reload::Restart, RESTART),
    spec("sources_default", Reload::Sighup, QUERIES),
    spec("source_aliases.{name}", Reload::Sighup, QUERIES),
    spec(
        "compatibility.inetnum_search_disabled",
        Reload::Sighup,
        QUERIES,
    ),
    spec(
        "compatibility.ipv4_only_route_set_members",
        Reload::Sighup,
        QUERIES,
    ),
    spec("compatibility.asdot_queries", Reload::Sighup, QUERIES),
    spec(
        "sources.{name}.authoritative",
        Reload::Sighup,
        "after SIGHUP, for all subsequent requests.",
    ),
    spec(
        "sources.{name}.authoritative_non_strict_mode_dangerous",
        Reload::Sighup,
        CHANGES,
    ),
    spec("sources.{name}.keep_journal", Reload::Sighup, CHANGES),
    spec("sources.{name}.nrtm_host", Reload::Sighup, MIRROR),
    spec("sources.{name}.nrtm_port", Reload::Sighup, MIRROR),
    spec(
        "sources.{name}.import_source",
        Reload::Sighup,
        "after SIGHUP, at the next full import.",
    ),
    spec(
        "sources.{name}.import_serial_source",
        Reload::Sighup,
        "see ``import_source``.",
    ),
    spec("sources.{name}.import_timer", Reload::Sighup, SIGHUP),
    spec(
        "sources.{name}.object_class_filter",
        Reload::Sighup,
        "after SIGHUP, at the next NRTM update or full import.",
    ),
    spec(
        "sources.{name}.export_destination",
        Reload::Sighup,
        "after SIGHUP, at the next ``export_timer``.",
    ),
    spec(
        "sources.{name}.export_destination_unfiltered",
        Reload::Sighup,
        "after SIGHUP, at the next ``export_timer``.",
    ),
    spec("sources.{name}.export_timer", Reload::Sighup, SIGHUP),
    spec("sources.{name}.nrtm_access_list", Reload::Sighup, REQUEST),
    spec(
        "sources.{name}.nrtm_access_list_unfiltered",
        Reload::Sighup,
        REQUEST,
    ),
    spec(
        "sources.{name}.nrtm_query_serial_days_limit",
        Reload::Sighup,
        REQUEST,
    ),
    spec(
        "sources.{name}.nrtm_query_serial_range_limit",
        Reload::Sighup,
        REQUEST,
    ),
    spec(
        "sources.{name}.nrtm_response_header",
        Reload::Sighup,
        REQUEST,
    ),
    spec(
        "sources.{name}.nrtm_dummified_attributes",
        Reload::Sighup,
        "after SIGHUP, upon next request/export.",
    ),
    spec(
        "sources.{name}.nrtm_dummified_object_classes",
        Reload::Sighup,
        "after SIGHUP, upon next request/export.",
    ),
    spec(
        "sources.{name}.nrtm_dummified_remarks",
        Reload::Sighup,
        REQUEST,
    ),
    spec(
        "sources.{name}.nrtm4_client_notification_file_url",
        Reload::Sighup,
        MIRROR,
    ),
    spec(
        "sources.{name}.nrtm4_client_initial_public_key",
        Reload::Sighup,
        MIRROR,
    ),
    spec(
        "sources.{name}.nrtm4_server_private_key",
        Reload::Sighup,
        MIRROR,
    ),
    spec(
        "sources.{name}.nrtm4_server_private_key_next",
        Reload::Sighup,
        MIRROR,
    ),
    spec(
        "sources.{name}.nrtm4_server_local_path",
        Reload::Sighup,
        MIRROR,
    ),
    spec(
        "sources.{name}.nrtm4_server_snapshot_frequency",
        Reload::Sighup,
        MIRROR,
    ),
    spec(
        "sources.{name}.strict_import_keycert_objects",
        Reload::Sighup,
        REQUEST,
    ),
    spec(
        "sources.{name}.rpki_excluded",
        Reload::Sighup,
        "after SIGHUP, upon next full ROA import.",
    ),
    spec(
        "sources.{name}.scopefilter_excluded",
        Reload::Sighup,
        "after SIGHUP, within a few minutes.",
    ),
    spec("sources.{name}.suspension_enabled", Reload::Sighup, CHANGES),
    spec(
        "sources.{name}.route_object_preference",
        Reload::Sighup,
        "after SIGHUP, after next periodic update.",
    ),
    spec(
        "sources.{name}.authoritative_retain_last_modified",
        Reload::Sighup,
        CHANGES,
    ),
    spec(
        "sources.{name}.nrtm3_client_timeout",
        Reload::Sighup,
        "after SIGHUP, at the next NRTM update.",
    ),
    // irrd-ng only: native standby replication (docs/architecture.md).
    // v4 has no such key; a v4-valid file never contains it.
    spec("ng_replication.secret", Reload::Restart, RESTART),
    spec("ng_replication.interface", Reload::Restart, RESTART),
    spec("ng_replication.port", Reload::Restart, RESTART),
    spec("ng_replication.active_host", Reload::Restart, RESTART),
    spec("ng_replication.active_port", Reload::Restart, RESTART),
    spec("ng_replication.tls_certificate", Reload::Restart, RESTART),
    spec("ng_replication.tls_key", Reload::Restart, RESTART),
    spec("ng_replication.tls_ca", Reload::Restart, RESTART),
    spec("ng_replication.tls_pin", Reload::Restart, RESTART),
    spec("ng_replication.tls_server_name", Reload::Restart, RESTART),
];

/// The irrd-ng-only top-level key for standby replication.
pub const NG_REPLICATION_KEY: &str = "ng_replication";

/// The leaf paths of `KNOWN_CONFIG_KEYS` (sources are checked separately).
fn known_leaves() -> Vec<String> {
    let mut leaves: Vec<String> = KEY_SPECS
        .iter()
        .map(|s| s.key)
        .filter(|k| {
            !k.starts_with("sources.")
                && !k.starts_with("access_lists.")
                && !k.starts_with("source_aliases.")
        })
        .filter(|k| !k.contains('{'))
        .map(str::to_owned)
        .collect();
    let set_classes = RPSL_SET_CLASSES
        .iter()
        .chain(std::iter::once(&AUTH_SET_CREATION_COMMON_KEY));
    for class in set_classes {
        leaves.push(format!("auth.set_creation.{class}.prefix_required"));
        leaves.push(format!("auth.set_creation.{class}.autnum_authentication"));
    }
    for hasher in PASSWORD_HASHERS {
        leaves.push(format!("auth.password_hashers.{hasher}"));
    }
    leaves
}

/// Every node of `KNOWN_CONFIG_KEYS`: leaves and the mappings above them.
static KNOWN_CONFIG_NODES: LazyLock<HashSet<String>> = LazyLock::new(|| {
    let mut nodes = HashSet::new();
    for leaf in known_leaves() {
        let mut prefix = String::new();
        for part in leaf.split('.') {
            if !prefix.is_empty() {
                prefix.push('.');
            }
            prefix.push_str(part);
            nodes.insert(prefix.clone());
        }
    }
    nodes
});

/// `KNOWN_CONFIG_KEYS.get(key) is not None`.
pub(crate) fn is_known_config_key(key: &str) -> bool {
    !key.contains("\\.") && KNOWN_CONFIG_NODES.contains(key)
}

pub(crate) fn is_known_source_key(key: &str) -> bool {
    KNOWN_SOURCES_KEYS.contains(&key)
}

/// The spec for a concrete setting name such as `sources.RIPE.keep_journal`.
pub fn spec_for(name: &str) -> Option<&'static KeySpec> {
    let parts: Vec<&str> = name.split('.').collect();
    KEY_SPECS.iter().find(|spec| {
        let pattern: Vec<&str> = spec.key.split('.').collect();
        pattern.len() == parts.len()
            && pattern.iter().zip(&parts).all(|(p, n)| match *p {
                "{name}" | "{list_name}" => true,
                "{set_class}" => RPSL_SET_CLASSES.contains(n) || *n == AUTH_SET_CREATION_COMMON_KEY,
                "{hasher}" => PASSWORD_HASHERS.contains(n),
                literal => literal == *n,
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_keys() {
        assert!(is_known_config_key("server"));
        assert!(is_known_config_key("server.http"));
        assert!(is_known_config_key("server.http.url"));
        assert!(is_known_config_key(
            "auth.set_creation.rtr-set.prefix_required"
        ));
        assert!(is_known_config_key("auth.set_creation.COMMON"));
        assert!(is_known_config_key("auth.password_hashers.md5-pw"));
        assert!(is_known_config_key("sources_default"));
        assert!(!is_known_config_key("auth.set_creation.not-a-real-set"));
        assert!(!is_known_config_key("server.http.url.x"));
        assert!(!is_known_config_key("access_lists"));
        assert!(!is_known_config_key("sources"));
    }

    #[test]
    fn reload_classes() {
        assert_eq!(spec_for("piddir").map(|s| s.reload), Some(Reload::Restart));
        assert_eq!(
            spec_for("sources.RIPE.keep_journal").map(|s| s.reload),
            Some(Reload::Sighup)
        );
        assert_eq!(
            spec_for("auth.set_creation.as-set.prefix_required").map(|s| s.reload),
            Some(Reload::NextUse)
        );
        assert_eq!(
            spec_for("access_lists.anything").map(|s| s.reload),
            Some(Reload::Sighup)
        );
        assert!(spec_for("auth.set_creation.foo.prefix_required").is_none());
        // Every key in v4's KNOWN_CONFIG_KEYS and KNOWN_SOURCES_KEYS has a spec.
        for leaf in known_leaves() {
            assert!(spec_for(&leaf).is_some(), "{leaf}");
        }
        for key in KNOWN_SOURCES_KEYS {
            assert!(spec_for(&format!("sources.X.{key}")).is_some(), "{key}");
        }
    }
}
