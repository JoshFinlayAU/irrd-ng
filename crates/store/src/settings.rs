//! The configuration the store consults while writing, as v4's
//! `DatabaseHandler` reads it through `get_setting()`.

use std::collections::HashMap;

/// Per-source settings the journal and status logic reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceSettings {
    /// `sources.X.keep_journal`
    pub keep_journal: bool,
    /// `sources.X.nrtm_host` is set (truthy).
    pub nrtm_host: bool,
    /// `sources.X.rpki_excluded`
    pub rpki_excluded: bool,
    /// `sources.X.scopefilter_excluded`
    pub scopefilter_excluded: bool,
    /// `sources.X.route_object_preference`
    pub route_object_preference: Option<i64>,
}

/// Settings the store reads, captured from `irrd.yaml` (plus environment
/// overrides) by the caller and replaced on SIGHUP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoreSettings {
    /// Per source. Sources missing here read as all-false, which is what
    /// `get_setting()` returns for an unconfigured source.
    pub sources: HashMap<String, SourceSettings>,
    /// `bool(get_setting("scopefilter"))`
    pub scopefilter_enabled: bool,
    /// `bool(get_setting("rpki.roa_source"))`
    pub rpki_enabled: bool,
    /// `readonly_standby`: every write is refused, as v4's handler does.
    pub readonly_standby: bool,
}

impl StoreSettings {
    /// The settings of one source.
    pub fn source(&self, source: &str) -> SourceSettings {
        self.sources.get(source).cloned().unwrap_or_default()
    }

    /// `is_serial_synchronised(..., settings_only=True)`: whether the
    /// configuration allows the source to use the mirror's serials.
    pub fn serials_synchronisable(&self, source: &str) -> bool {
        let s = self.source(source);
        (!self.scopefilter_enabled || s.scopefilter_excluded)
            && (!self.rpki_enabled || s.rpki_excluded)
            && s.route_object_preference.is_none_or(|p| p == 0)
            && s.nrtm_host
    }

    /// Whether any source has `route_object_preference` set, which makes
    /// v4 re-evaluate route preference before every commit.
    pub fn route_preference_enabled(&self) -> bool {
        self.sources
            .values()
            .any(|s| s.route_object_preference.is_some_and(|p| p != 0))
    }
}
