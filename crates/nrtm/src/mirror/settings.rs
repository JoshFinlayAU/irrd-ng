//! The settings the mirroring client reads, captured from `irrd.yaml`
//! (with environment overrides) as v4's `get_setting()` returns them. The
//! daemon builds a new snapshot on SIGHUP; a run in progress keeps the one
//! it started with.

use std::collections::HashSet;

/// v4's `DEFAULT_SOURCE_IMPORT_TIMER`.
pub const DEFAULT_SOURCE_IMPORT_TIMER: i64 = 300;
/// v4's `DEFAULT_SOURCE_IMPORT_TIMER_NRTM4` (0 with
/// `IRRD_TESTING_FAST_SCHEDULER_OVERRIDE`).
pub const DEFAULT_SOURCE_IMPORT_TIMER_NRTM4: i64 = 60;
/// v4's `DEFAULT_SOURCE_EXPORT_TIMER`.
pub const DEFAULT_SOURCE_EXPORT_TIMER: i64 = 3600;
/// v4's `DEFAULT_SOURCE_EXPORT_TIMER_NRTM4`: how often the NRTMv4 server
/// runs (0 with `IRRD_TESTING_FAST_SCHEDULER_OVERRIDE`).
pub const DEFAULT_SOURCE_EXPORT_TIMER_NRTM4: i64 = 60;
/// v4's `DEFAULT_SOURCE_NRTM4_SERVER_SNAPSHOT_FREQUENCY`, in seconds.
pub const DEFAULT_SOURCE_NRTM4_SERVER_SNAPSHOT_FREQUENCY: i64 = 3600 * 4;
/// v4's `DEFAULT_SOURCE_NRTM3_CLIENT_TIMEOUT`.
pub const DEFAULT_SOURCE_NRTM3_CLIENT_TIMEOUT: i64 = 15;
/// v4's `DEFAULT_SOURCE_NRTM_PORT`.
pub const DEFAULT_SOURCE_NRTM_PORT: i64 = 43;
/// v4's `MIRROR_FREQUENCY`: seconds between scheduler runs (1 with
/// `IRRD_TESTING_FAST_SCHEDULER_OVERRIDE`).
pub const MIRROR_FREQUENCY: u64 = 3;

/// One source's mirroring settings.
#[derive(Debug, Clone)]
pub struct SourceMirrorSettings {
    /// The source name.
    pub name: String,
    /// `import_source`, a string made a one-item list; `None` when unset
    /// or falsy.
    pub import_source: Option<Vec<String>>,
    /// `str()` of the list v4 logs (`['ftp://...']`).
    pub import_source_repr: String,
    /// `import_serial_source`, `None` when unset or falsy.
    pub import_serial_source: Option<String>,
    /// `str()` of `import_serial_source` as v4 logs it (`None` if unset).
    pub import_serial_source_str: String,
    /// `nrtm_host`, when truthy.
    pub nrtm_host: Option<String>,
    /// `int(nrtm_port)`, or the `ValueError` text.
    pub nrtm_port: Result<i64, String>,
    /// `int(nrtm3_client_timeout)`, or the `ValueError` text.
    pub nrtm3_client_timeout: Result<i64, String>,
    /// `int(import_timer)` with v4's default for the kind of source.
    pub import_timer: i64,
    /// `nrtm4_client_notification_file_url`, when truthy.
    pub nrtm4_client_notification_file_url: Option<String>,
    /// `nrtm4_client_initial_public_key`, when truthy.
    pub nrtm4_client_initial_public_key: Option<String>,
    /// `get_object_class_filter_for_source()`.
    pub object_class_filter: Option<Vec<String>>,
    /// `strict_import_keycert_objects`
    pub strict_import_keycert_objects: bool,
    /// `get_setting(f"sources.{name}.rpki_excluded")`
    pub rpki_excluded: bool,
    /// `export_destination` or `export_destination_unfiltered` is set
    /// (the export runner arrives in Phase 6).
    pub runs_rpsl_export: bool,
    /// `int(export_timer)`.
    pub export_timer: i64,
    /// `nrtm4_server_private_key` is set.
    pub runs_nrtm4_server: bool,
    /// `export_destination`, when truthy.
    pub export_destination: Option<String>,
    /// `export_destination_unfiltered`, when truthy.
    pub export_destination_unfiltered: Option<String>,
    /// The `nrtm_dummified_*` settings, for exports and NRTMv4 files.
    pub dummify: rpsl::text::DummifySettings,
    /// `nrtm4_server_local_path`, when truthy.
    pub nrtm4_server_local_path: Option<String>,
    /// `nrtm4_server_private_key`, when truthy.
    pub nrtm4_server_private_key: Option<String>,
    /// `nrtm4_server_private_key_next`, when truthy.
    pub nrtm4_server_private_key_next: Option<String>,
    /// `nrtm4_server_snapshot_frequency` in seconds, with v4's default.
    pub nrtm4_server_snapshot_frequency: i64,
}

impl Default for SourceMirrorSettings {
    /// A source with nothing set: v4's defaults.
    fn default() -> Self {
        SourceMirrorSettings {
            name: String::new(),
            import_source: None,
            import_source_repr: "None".into(),
            import_serial_source: None,
            import_serial_source_str: "None".into(),
            nrtm_host: None,
            nrtm_port: Ok(DEFAULT_SOURCE_NRTM_PORT),
            nrtm3_client_timeout: Ok(DEFAULT_SOURCE_NRTM3_CLIENT_TIMEOUT),
            import_timer: DEFAULT_SOURCE_IMPORT_TIMER,
            nrtm4_client_notification_file_url: None,
            nrtm4_client_initial_public_key: None,
            object_class_filter: None,
            strict_import_keycert_objects: false,
            rpki_excluded: false,
            runs_rpsl_export: false,
            export_timer: DEFAULT_SOURCE_EXPORT_TIMER,
            runs_nrtm4_server: false,
            export_destination: None,
            export_destination_unfiltered: None,
            dummify: rpsl::text::DummifySettings::default(),
            nrtm4_server_local_path: None,
            nrtm4_server_private_key: None,
            nrtm4_server_private_key_next: None,
            nrtm4_server_snapshot_frequency: DEFAULT_SOURCE_NRTM4_SERVER_SNAPSHOT_FREQUENCY,
        }
    }
}

impl SourceMirrorSettings {
    /// `import_source or nrtm_host or nrtm4_client_notification_file_url`.
    pub fn is_mirror(&self) -> bool {
        self.import_source.is_some()
            || self.nrtm_host.is_some()
            || self.nrtm4_client_notification_file_url.is_some()
    }
}

/// Everything the mirroring client reads.
#[derive(Debug, Clone, Default)]
pub struct MirrorSettings {
    /// `readonly_standby`: no mirroring at all.
    pub readonly_standby: bool,
    /// `bool(rpki.roa_source)`
    pub rpki_enabled: bool,
    /// Sources whose settings dict has `rpki_excluded` (what
    /// `BulkRouteROAValidator` reads).
    pub rpki_excluded_sources: HashSet<String>,
    /// The scope filter.
    pub scopefilter: rpki::ScopeFilterConfig,
    /// RPSL parser settings.
    pub rpsl: rpsl::RpslSettings,
    /// `int(download_timeout)`
    pub download_timeout: u64,
    /// `IRRD_TESTING_FAST_SCHEDULER_OVERRIDE` is set in the environment.
    pub fast_scheduler: bool,
    /// The sources, in configuration order.
    pub sources: Vec<SourceMirrorSettings>,
}

impl MirrorSettings {
    /// One source's settings (all unset for an unknown source).
    pub fn source(&self, name: &str) -> SourceMirrorSettings {
        self.sources
            .iter()
            .find(|s| s.name == name)
            .cloned()
            .unwrap_or_else(|| SourceMirrorSettings {
                name: name.to_owned(),
                ..Default::default()
            })
    }

    /// Seconds between scheduler runs.
    pub fn mirror_frequency(&self) -> u64 {
        if self.fast_scheduler {
            1
        } else {
            MIRROR_FREQUENCY
        }
    }

    /// The NRTMv4 server's timer.
    pub fn export_timer_nrtm4(&self) -> i64 {
        if self.fast_scheduler {
            0
        } else {
            DEFAULT_SOURCE_EXPORT_TIMER_NRTM4
        }
    }

    /// The default `import_timer` for an NRTMv4 client source.
    pub fn default_import_timer_nrtm4(&self) -> i64 {
        if self.fast_scheduler {
            0
        } else {
            DEFAULT_SOURCE_IMPORT_TIMER_NRTM4
        }
    }
}
