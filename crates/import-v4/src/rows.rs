//! One struct per v4 table, field for field.
//!
//! Field names are v4's column names (`override` becomes `override_`), and
//! every column of the 4.5 schema (alembic head `e1e649b5f8bb`) is carried,
//! including v4's own UUID primary keys, so foreign keys between the web UI
//! tables and `rpsl_objects` stay intact through the import.

use postgres::Row;
use uuid::Uuid;

use crate::types::{
    DatabaseOperation, Inet, JournalEntryOrigin, JsonText, NumericU128, RoutePreferenceStatus,
    RpkiStatus, ScopeFilterStatus, Timestamp, UpdateRequestType,
};

/// A v4 table the importer reads.
pub trait V4Table: Sized {
    /// The table name in v4's schema.
    const TABLE: &'static str;
    /// The select list, one expression per field, in field order.
    const COLUMNS: &'static [&'static str];

    fn from_row(row: &Row) -> Result<Self, postgres::Error>;
}

macro_rules! v4_table {
    (
        $(#[$doc:meta])*
        $name:ident = $table:literal {
            $($field:ident : $ty:ty = $sql:literal),+ $(,)?
        }
    ) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq)]
        pub struct $name {
            $(pub $field: $ty),+
        }

        impl V4Table for $name {
            const TABLE: &'static str = $table;
            const COLUMNS: &'static [&'static str] = &[$($sql),+];

            fn from_row(row: &Row) -> Result<Self, postgres::Error> {
                let mut _idx = 0usize;
                Ok(Self {
                    $($field: {
                        let v = row.try_get::<_, $ty>(_idx)?;
                        _idx += 1;
                        v
                    }),+
                })
            }
        }
    };
}

v4_table!(
    /// `rpsl_objects`: every RPSL object, keyed by (rpsl_pk, source, object_class).
    RpslObject = "rpsl_objects" {
        pk: Uuid = "pk",
        rpsl_pk: String = "rpsl_pk",
        source: String = "source",
        object_class: String = "object_class",
        parsed_data: JsonText = "parsed_data::text",
        object_text: String = "object_text",
        ip_version: Option<i32> = "ip_version",
        ip_first: Option<Inet> = "ip_first",
        ip_last: Option<Inet> = "ip_last",
        ip_size: Option<NumericU128> = "ip_size::text",
        prefix_length: Option<i32> = "prefix_length",
        prefix: Option<Inet> = "prefix",
        asn_first: Option<i64> = "asn_first",
        asn_last: Option<i64> = "asn_last",
        rpki_status: RpkiStatus = "rpki_status",
        scopefilter_status: ScopeFilterStatus = "scopefilter_status",
        route_preference_status: RoutePreferenceStatus = "route_preference_status",
        created: Timestamp = "created",
        updated: Timestamp = "updated",
    }
);

v4_table!(
    /// `rpsl_database_journal`: the NRTM journal. `serial_nrtm` is per
    /// source and must survive unchanged; `serial_global` orders the journal
    /// across sources (nullable in the migrated schema, never null in
    /// practice).
    JournalEntry = "rpsl_database_journal" {
        pk: Uuid = "pk",
        serial_global: Option<i64> = "serial_global",
        rpsl_pk: String = "rpsl_pk",
        source: String = "source",
        origin: JournalEntryOrigin = "origin",
        serial_nrtm: i32 = "serial_nrtm",
        operation: DatabaseOperation = "operation",
        object_class: String = "object_class",
        object_text: String = "object_text",
        timestamp: Timestamp = "timestamp",
    }
);

v4_table!(
    /// `database_status`: one row per source, including NRTMv4 client and
    /// server state.
    DatabaseStatus = "database_status" {
        pk: Uuid = "pk",
        source: String = "source",
        serial_oldest_seen: Option<i32> = "serial_oldest_seen",
        serial_newest_seen: Option<i32> = "serial_newest_seen",
        serial_oldest_journal: Option<i32> = "serial_oldest_journal",
        serial_newest_journal: Option<i32> = "serial_newest_journal",
        serial_last_export: Option<i32> = "serial_last_export",
        serial_newest_mirror: Option<i32> = "serial_newest_mirror",
        nrtm4_client_session_id: Option<Uuid> = "nrtm4_client_session_id",
        nrtm4_client_version: Option<i32> = "nrtm4_client_version",
        nrtm4_client_current_key: Option<String> = "nrtm4_client_current_key",
        nrtm4_client_next_key: Option<String> = "nrtm4_client_next_key",
        nrtm4_client_previous_file_hashes: Option<JsonText> = "nrtm4_client_previous_file_hashes::text",
        nrtm4_server_session_id: Option<Uuid> = "nrtm4_server_session_id",
        nrtm4_server_version: Option<i32> = "nrtm4_server_version",
        nrtm4_server_last_update_notification_file_update: Option<Timestamp> = "nrtm4_server_last_update_notification_file_update",
        nrtm4_server_last_snapshot_version: Option<i32> = "nrtm4_server_last_snapshot_version",
        nrtm4_server_last_snapshot_global_serial: Option<i32> = "nrtm4_server_last_snapshot_global_serial",
        nrtm4_server_last_snapshot_timestamp: Option<Timestamp> = "nrtm4_server_last_snapshot_timestamp",
        nrtm4_server_last_snapshot_filename: Option<String> = "nrtm4_server_last_snapshot_filename",
        nrtm4_server_last_snapshot_hash: Option<String> = "nrtm4_server_last_snapshot_hash",
        nrtm4_server_previous_deltas: Option<JsonText> = "nrtm4_server_previous_deltas::text",
        force_reload: bool = "force_reload",
        synchronised_serials: bool = "synchronised_serials",
        last_error: Option<String> = "last_error",
        last_error_timestamp: Option<Timestamp> = "last_error_timestamp",
        rpsl_data_updated: Timestamp = "rpsl_data_updated",
        created: Timestamp = "created",
        updated: Timestamp = "updated",
    }
);

v4_table!(
    /// `roa_object`: ROAs from the configured RPKI source and SLURM.
    Roa = "roa_object" {
        pk: Uuid = "pk",
        prefix: Inet = "prefix",
        asn: i64 = "asn",
        max_length: i32 = "max_length",
        trust_anchor: Option<String> = "trust_anchor",
        ip_version: i32 = "ip_version",
        created: Timestamp = "created",
    }
);

v4_table!(
    /// `rpsl_objects_suspended`: objects taken out of service by suspension.
    SuspendedObject = "rpsl_objects_suspended" {
        pk: Uuid = "pk",
        rpsl_pk: String = "rpsl_pk",
        source: String = "source",
        object_class: String = "object_class",
        object_text: String = "object_text",
        mntners: Vec<String> = "mntners",
        timestamp: Timestamp = "timestamp",
        original_created: Timestamp = "original_created",
        original_updated: Timestamp = "original_updated",
    }
);

v4_table!(
    /// `protected_rpsl_name`: names of deleted person, role and mntner
    /// objects that may not be reused.
    ProtectedName = "protected_rpsl_name" {
        pk: Uuid = "pk",
        rpsl_pk: String = "rpsl_pk",
        source: String = "source",
        object_class: String = "object_class",
        protected_name: String = "protected_name",
        created: Timestamp = "created",
    }
);

v4_table!(
    /// `setting`: v4's internal key/value state (the web UI secret key).
    Setting = "setting" {
        name: String = "name",
        value: Option<String> = "value",
        created: Timestamp = "created",
    }
);

v4_table!(
    /// `auth_user`: web UI users.
    AuthUser = "auth_user" {
        pk: Uuid = "pk",
        email: String = "email",
        name: String = "name",
        password: String = "password",
        totp_secret: Option<String> = "totp_secret",
        totp_last_used: Option<String> = "totp_last_used",
        active: bool = "active",
        override_: bool = "override",
        created: Timestamp = "created",
        updated: Timestamp = "updated",
    }
);

v4_table!(
    /// `auth_mntner`: mntners migrated to web UI auth. `rpsl_mntner_obj_id`
    /// is the `pk` of the mntner in `rpsl_objects`.
    AuthMntner = "auth_mntner" {
        pk: Uuid = "pk",
        rpsl_mntner_pk: String = "rpsl_mntner_pk",
        rpsl_mntner_obj_id: Uuid = "rpsl_mntner_obj_id",
        rpsl_mntner_source: String = "rpsl_mntner_source",
        migration_token: Option<String> = "migration_token",
        created: Timestamp = "created",
        updated: Timestamp = "updated",
    }
);

v4_table!(
    /// `auth_permission`: which users may act for which migrated mntners.
    AuthPermission = "auth_permission" {
        pk: Uuid = "pk",
        user_id: Option<Uuid> = "user_id",
        mntner_id: Option<Uuid> = "mntner_id",
        user_management: bool = "user_management",
        created: Timestamp = "created",
        updated: Timestamp = "updated",
    }
);

v4_table!(
    /// `auth_api_token`: API keys, live for `/v1/submit/` and email.
    AuthApiToken = "auth_api_token" {
        pk: Uuid = "pk",
        token: Option<Uuid> = "token",
        name: String = "name",
        creator_id: Option<Uuid> = "creator_id",
        mntner_id: Option<Uuid> = "mntner_id",
        ip_restriction: Option<String> = "ip_restriction",
        enabled_webapi: bool = "enabled_webapi",
        enabled_email: bool = "enabled_email",
        created: Timestamp = "created",
        updated: Timestamp = "updated",
    }
);

v4_table!(
    /// `auth_webauthn`: WebAuthn credentials of web UI users.
    AuthWebauthn = "auth_webauthn" {
        pk: Uuid = "pk",
        user_id: Option<Uuid> = "user_id",
        name: String = "name",
        credential_id: Vec<u8> = "credential_id",
        credential_public_key: Vec<u8> = "credential_public_key",
        credential_sign_count: i32 = "credential_sign_count",
        created: Timestamp = "created",
        last_used: Timestamp = "last_used",
    }
);

v4_table!(
    /// `change_log`: the web UI's record of authoritative changes.
    ChangeLog = "change_log" {
        pk: Uuid = "pk",
        auth_by_user_id: Option<Uuid> = "auth_by_user_id",
        auth_by_user_email: Option<String> = "auth_by_user_email",
        auth_by_api_key_id: Option<Uuid> = "auth_by_api_key_id",
        auth_by_api_key_id_fixed: Option<Uuid> = "auth_by_api_key_id_fixed",
        auth_through_mntner_id: Option<Uuid> = "auth_through_mntner_id",
        auth_through_rpsl_mntner_pk: Option<String> = "auth_through_rpsl_mntner_pk",
        auth_by_rpsl_mntner_password: bool = "auth_by_rpsl_mntner_password",
        auth_by_rpsl_mntner_pgp_key: bool = "auth_by_rpsl_mntner_pgp_key",
        auth_by_override: Option<bool> = "auth_by_override",
        from_email: Option<String> = "from_email",
        from_ip: Option<Inet> = "from_ip",
        auth_change_descr: Option<String> = "auth_change_descr",
        auth_affected_user_id: Option<Uuid> = "auth_affected_user_id",
        auth_affected_mntner_id: Option<Uuid> = "auth_affected_mntner_id",
        rpsl_target_request_type: Option<UpdateRequestType> = "rpsl_target_request_type",
        rpsl_target_pk: Option<String> = "rpsl_target_pk",
        rpsl_target_source: Option<String> = "rpsl_target_source",
        rpsl_target_object_class: Option<String> = "rpsl_target_object_class",
        rpsl_target_object_text_old: Option<String> = "rpsl_target_object_text_old",
        rpsl_target_object_text_new: Option<String> = "rpsl_target_object_text_new",
        timestamp: Timestamp = "timestamp",
    }
);

/// A batch of rows from one table, as handed to a [`crate::Sink`].
#[derive(Debug, Clone, PartialEq)]
pub enum Batch {
    RpslObjects(Vec<RpslObject>),
    Journal(Vec<JournalEntry>),
    DatabaseStatus(Vec<DatabaseStatus>),
    Roas(Vec<Roa>),
    Suspended(Vec<SuspendedObject>),
    ProtectedNames(Vec<ProtectedName>),
    Settings(Vec<Setting>),
    AuthUsers(Vec<AuthUser>),
    AuthMntners(Vec<AuthMntner>),
    AuthPermissions(Vec<AuthPermission>),
    AuthApiTokens(Vec<AuthApiToken>),
    AuthWebauthn(Vec<AuthWebauthn>),
    ChangeLog(Vec<ChangeLog>),
}

impl Batch {
    pub fn table(&self) -> &'static str {
        match self {
            Batch::RpslObjects(_) => RpslObject::TABLE,
            Batch::Journal(_) => JournalEntry::TABLE,
            Batch::DatabaseStatus(_) => DatabaseStatus::TABLE,
            Batch::Roas(_) => Roa::TABLE,
            Batch::Suspended(_) => SuspendedObject::TABLE,
            Batch::ProtectedNames(_) => ProtectedName::TABLE,
            Batch::Settings(_) => Setting::TABLE,
            Batch::AuthUsers(_) => AuthUser::TABLE,
            Batch::AuthMntners(_) => AuthMntner::TABLE,
            Batch::AuthPermissions(_) => AuthPermission::TABLE,
            Batch::AuthApiTokens(_) => AuthApiToken::TABLE,
            Batch::AuthWebauthn(_) => AuthWebauthn::TABLE,
            Batch::ChangeLog(_) => ChangeLog::TABLE,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Batch::RpslObjects(v) => v.len(),
            Batch::Journal(v) => v.len(),
            Batch::DatabaseStatus(v) => v.len(),
            Batch::Roas(v) => v.len(),
            Batch::Suspended(v) => v.len(),
            Batch::ProtectedNames(v) => v.len(),
            Batch::Settings(v) => v.len(),
            Batch::AuthUsers(v) => v.len(),
            Batch::AuthMntners(v) => v.len(),
            Batch::AuthPermissions(v) => v.len(),
            Batch::AuthApiTokens(v) => v.len(),
            Batch::AuthWebauthn(v) => v.len(),
            Batch::ChangeLog(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
