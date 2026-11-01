//! The `irrd.yaml` settings the update handlers read with `get_setting()`.
//!
//! Built by the caller from the loaded configuration (the `cli` crate), so
//! this crate stays independent of the `config` crate, like `rpsl`.

use std::collections::HashMap;

use rpsl::RpslSettings;

/// Per-source settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceSubmitSettings {
    /// `sources.X.authoritative`
    pub authoritative: bool,
    /// `sources.X.suspension_enabled`
    pub suspension_enabled: bool,
    /// `sources.X.authoritative_non_strict_mode_dangerous`
    pub non_strict_mode: bool,
    /// `get_object_class_filter_for_source(X)`: lower-cased, stripped.
    pub object_class_filter: Option<Vec<String>>,
    /// `sources.X.rpki_excluded`
    pub rpki_excluded: bool,
}

/// `RPSLSetAutnumAuthenticationMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutnumAuthMode {
    /// `disabled`
    Disabled,
    /// `opportunistic`
    Opportunistic,
    /// `required`
    Required,
}

impl AutnumAuthMode {
    /// `getattr(RPSLSetAutnumAuthenticationMode, setting.upper())`.
    pub fn from_setting(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "DISABLED" => Some(AutnumAuthMode::Disabled),
            "OPPORTUNISTIC" => Some(AutnumAuthMode::Opportunistic),
            "REQUIRED" => Some(AutnumAuthMode::Required),
            _ => None,
        }
    }
}

/// Everything submissions read from `irrd.yaml`.
#[derive(Debug, Clone)]
pub struct SubmitSettings {
    /// Parser settings.
    pub rpsl: RpslSettings,
    /// Per source, keyed by upper case name.
    pub sources: HashMap<String, SourceSubmitSettings>,
    /// `auth.override_password`
    pub override_password: Option<String>,
    /// `auth.authenticate_parents_route_creation`
    pub authenticate_parents_route_creation: bool,
    /// `auth.set_creation.<class>.autnum_authentication`, by class name or
    /// `COMMON`.
    pub set_autnum_authentication: HashMap<String, String>,
    /// `rpki.roa_source` is set.
    pub rpki_enabled: bool,
    /// `rpki.roa_import_timer`, as v4 formats it into a message.
    pub roa_import_timer: String,
    /// The scope filter.
    pub scopefilter: rpki::ScopeFilterConfig,
    /// `email.*` for replies and notifications.
    pub mail: mail::MailSettings,
    /// `email.notification_header`
    pub notification_header: String,
}

impl Default for SubmitSettings {
    fn default() -> Self {
        SubmitSettings {
            rpsl: RpslSettings::default(),
            sources: HashMap::new(),
            override_password: None,
            authenticate_parents_route_creation: true,
            set_autnum_authentication: HashMap::from([(
                "COMMON".to_owned(),
                "opportunistic".to_owned(),
            )]),
            rpki_enabled: false,
            roa_import_timer: "3600".to_owned(),
            scopefilter: rpki::ScopeFilterConfig::default(),
            mail: mail::MailSettings::default(),
            notification_header: crate::messages::DEFAULT_NOTIFICATION_HEADER.to_owned(),
        }
    }
}

impl SubmitSettings {
    /// The settings of one source; unknown sources get v4's `None`s.
    pub fn source(&self, name: &str) -> SourceSubmitSettings {
        self.sources.get(name).cloned().unwrap_or_default()
    }

    /// `RPSLSetAutnumAuthenticationMode.for_set_name(class)`.
    pub fn autnum_mode(&self, class: &str) -> AutnumAuthMode {
        let setting = self
            .set_autnum_authentication
            .get(class)
            .filter(|s| !s.is_empty())
            .or_else(|| self.set_autnum_authentication.get("COMMON"));
        setting
            .and_then(|s| AutnumAuthMode::from_setting(s))
            .unwrap_or(AutnumAuthMode::Opportunistic)
    }
}
