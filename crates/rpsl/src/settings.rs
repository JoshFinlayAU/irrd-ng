//! The `irrd.yaml` settings the RPSL parser consults.
//!
//! v4's parser calls `get_setting()` directly. irrd-ng keeps this crate
//! independent of the `config` crate: the caller builds an [`RpslSettings`]
//! from the loaded configuration and passes it in. `Default` matches the
//! parity harness configuration (`parity/v4/irrd.yaml`), which equals v4's
//! defaults except where noted per field.

use std::collections::HashMap;

/// `auth.password_hashers.<name>` availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HasherAvailability {
    /// `enabled`: accepted in new and existing objects.
    Enabled,
    /// `legacy`: accepted in existing objects only (non-strict parsing).
    Legacy,
    /// `disabled`: never accepted.
    Disabled,
}

/// A password hash scheme, in v4's `PASSWORD_HASHERS_ALL` order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordHasher {
    /// `CRYPT-PW` (DES crypt).
    CryptPw,
    /// `MD5-PW` (MD5 crypt).
    Md5Pw,
    /// `BCRYPT-PW`.
    BcryptPw,
}

impl PasswordHasher {
    /// All schemes in v4's order.
    pub const ALL: [PasswordHasher; 3] = [
        PasswordHasher::CryptPw,
        PasswordHasher::Md5Pw,
        PasswordHasher::BcryptPw,
    ];

    /// The scheme as written in `auth:` lines.
    pub fn scheme(&self) -> &'static str {
        match self {
            PasswordHasher::CryptPw => "CRYPT-PW",
            PasswordHasher::Md5Pw => "MD5-PW",
            PasswordHasher::BcryptPw => "BCRYPT-PW",
        }
    }
}

/// Per-source settings used when rendering object text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SourceRenderSettings {
    /// `sources.<name>.authoritative`
    pub authoritative: bool,
    /// `sources.<name>.authoritative_retain_last_modified`
    pub authoritative_retain_last_modified: bool,
}

/// Everything the RPSL parser reads from `irrd.yaml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpslSettings {
    /// `auth.password_hashers.crypt-pw`. v4 default: `legacy`.
    pub crypt_pw: HasherAvailability,
    /// `auth.password_hashers.md5-pw`. v4 default: `enabled`; the parity
    /// harness configuration sets `legacy`, which is this default.
    pub md5_pw: HasherAvailability,
    /// `auth.password_hashers.bcrypt-pw`. v4 default: `enabled`.
    pub bcrypt_pw: HasherAvailability,
    /// `auth.set_creation.<class>.prefix_required`, keyed by object class or
    /// `COMMON`. v4 default: `COMMON: true`. Only used by
    /// `clean_for_create`.
    pub set_creation_prefix_required: HashMap<String, bool>,
    /// `compatibility.asdot_queries`. v4 default: false. The RPSL fields never
    /// permit asdot, so this only matters to callers of
    /// [`crate::parse_as_number`] that do.
    pub asdot_queries: bool,
    /// `sources.<name>.authoritative` and
    /// `sources.<name>.authoritative_retain_last_modified`, keyed by upper
    /// case source name. Only used when rendering with a new
    /// `last-modified`.
    pub sources: HashMap<String, SourceRenderSettings>,
}

impl Default for RpslSettings {
    fn default() -> Self {
        RpslSettings {
            crypt_pw: HasherAvailability::Legacy,
            md5_pw: HasherAvailability::Legacy,
            bcrypt_pw: HasherAvailability::Enabled,
            set_creation_prefix_required: HashMap::from([("COMMON".to_owned(), true)]),
            asdot_queries: false,
            sources: HashMap::from([(
                "TEST".to_owned(),
                SourceRenderSettings {
                    authoritative: true,
                    authoritative_retain_last_modified: false,
                },
            )]),
        }
    }
}

impl RpslSettings {
    /// Availability of one scheme.
    pub fn availability(&self, hasher: PasswordHasher) -> HasherAvailability {
        match hasher {
            PasswordHasher::CryptPw => self.crypt_pw,
            PasswordHasher::Md5Pw => self.md5_pw,
            PasswordHasher::BcryptPw => self.bcrypt_pw,
        }
    }

    /// `get_password_hashers(permit_legacy)`: the usable schemes in order.
    pub fn password_hashers(&self, permit_legacy: bool) -> Vec<PasswordHasher> {
        PasswordHasher::ALL
            .into_iter()
            .filter(|h| match self.availability(*h) {
                HasherAvailability::Enabled => true,
                HasherAvailability::Legacy => permit_legacy,
                HasherAvailability::Disabled => false,
            })
            .collect()
    }
}
