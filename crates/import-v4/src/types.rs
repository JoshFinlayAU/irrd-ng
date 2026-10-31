//! Column types of v4's tables that need more than a Rust primitive.
//!
//! Each one decodes PostgreSQL's binary wire format directly, so a value
//! reaches the store exactly as v4 stored it, and renders the way the
//! canonical export (`parity/tools/export_v4.py`) writes it.

use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use postgres::types::{FromSql, Kind, Type};

type BoxError = Box<dyn StdError + Sync + Send>;

/// A `timestamp with time zone`: microseconds since the Unix epoch, UTC.
///
/// PostgreSQL keeps exactly this precision, so nothing is lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub i64);

/// Microseconds between 1970-01-01 and PostgreSQL's epoch, 2000-01-01.
const PG_EPOCH_OFFSET_US: i64 = 946_684_800_000_000;

impl Timestamp {
    /// Microseconds since 1970-01-01T00:00:00Z.
    pub fn unix_micros(self) -> i64 {
        self.0
    }
}

impl<'a> FromSql<'a> for Timestamp {
    fn from_sql(_: &Type, raw: &'a [u8]) -> Result<Self, BoxError> {
        let bytes: [u8; 8] = raw.try_into().map_err(|_| "invalid timestamptz length")?;
        let pg = i64::from_be_bytes(bytes);
        if pg == i64::MAX || pg == i64::MIN {
            return Err("infinite timestamps are not supported".into());
        }
        Ok(Timestamp(pg + PG_EPOCH_OFFSET_US))
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::TIMESTAMPTZ
    }
}

/// `YYYY-MM-DDTHH:MM:SS.ffffffZ`, always with six fraction digits.
impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.div_euclid(1_000_000);
        let micros = self.0.rem_euclid(1_000_000);
        let days = secs.div_euclid(86_400);
        let sod = secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        write!(
            f,
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{micros:06}Z",
            sod / 3600,
            sod % 3600 / 60,
            sod % 60
        )
    }
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// An `inet` or `cidr` value: an address and a mask length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Inet {
    pub addr: IpAddr,
    pub prefix_len: u8,
    /// Whether PostgreSQL holds it as `cidr` (always printed with a mask)
    /// rather than `inet` (mask omitted when it covers the whole address).
    pub is_cidr: bool,
}

impl Inet {
    fn max_len(&self) -> u8 {
        match self.addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }
}

impl<'a> FromSql<'a> for Inet {
    fn from_sql(_: &Type, raw: &'a [u8]) -> Result<Self, BoxError> {
        // family, bits, is_cidr, address length, address bytes
        let [family, bits, is_cidr, nb, rest @ ..] = raw else {
            return Err("invalid inet value".into());
        };
        let addr = match (*family, *nb, rest) {
            (2, 4, &[a, b, c, d]) => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            (3, 16, octets) if octets.len() == 16 => {
                let mut buf = [0u8; 16];
                buf.copy_from_slice(octets);
                IpAddr::V6(Ipv6Addr::from(buf))
            }
            _ => return Err("invalid inet value".into()),
        };
        let inet = Inet {
            addr,
            prefix_len: *bits,
            is_cidr: *is_cidr != 0,
        };
        if inet.prefix_len > inet.max_len() {
            return Err("invalid inet mask length".into());
        }
        Ok(inet)
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::INET || *ty == Type::CIDR
    }
}

/// PostgreSQL's text output: `inet` drops a full-length mask, `cidr` never
/// does.
impl fmt::Display for Inet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)?;
        if self.is_cidr || self.prefix_len != self.max_len() {
            write!(f, "/{}", self.prefix_len)?;
        }
        Ok(())
    }
}

/// A `numeric` holding a non-negative integer (`rpsl_objects.ip_size`,
/// up to 2^128). Selected as `::text`, because the binary numeric format is
/// base 10000 digits and the text form is exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NumericU128(pub u128);

pub(crate) fn parse_numeric_u128(text: &str) -> Result<u128, BoxError> {
    Ok(text.parse::<u128>()?)
}

impl<'a> FromSql<'a> for NumericU128 {
    fn from_sql(_: &Type, raw: &'a [u8]) -> Result<Self, BoxError> {
        Ok(NumericU128(parse_numeric_u128(std::str::from_utf8(raw)?)?))
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::TEXT
    }
}

impl fmt::Display for NumericU128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A `jsonb` value, as PostgreSQL's text rendering of it (selected as
/// `::text`). Kept as text so nothing is reinterpreted on the way through;
/// key order is jsonb's own, so compare it parsed, not as bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JsonText(pub String);

impl<'a> FromSql<'a> for JsonText {
    fn from_sql(_: &Type, raw: &'a [u8]) -> Result<Self, BoxError> {
        Ok(JsonText(std::str::from_utf8(raw)?.to_owned()))
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::TEXT
    }
}

macro_rules! pg_enum {
    ($(#[$doc:meta])* $name:ident: $pg:literal { $($variant:ident = $label:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            /// The PostgreSQL type name in v4's schema.
            pub const PG_TYPE: &'static str = $pg;

            /// The label v4 stores.
            pub fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $label),+
                }
            }

            pub fn from_label(label: &str) -> Option<Self> {
                match label {
                    $($label => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }

        impl<'a> FromSql<'a> for $name {
            fn from_sql(_: &Type, raw: &'a [u8]) -> Result<Self, BoxError> {
                let label = std::str::from_utf8(raw)?;
                Self::from_label(label)
                    .ok_or_else(|| format!("unknown {} label {label:?}", $pg).into())
            }

            fn accepts(ty: &Type) -> bool {
                matches!(ty.kind(), Kind::Enum(_)) && ty.name() == $pg
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.label())
            }
        }
    };
}

pg_enum!(
    /// `rpsl_objects.rpki_status`.
    RpkiStatus: "rpkistatus" {
        Valid = "valid",
        Invalid = "invalid",
        NotFound = "not_found",
    }
);

pg_enum!(
    /// `rpsl_objects.scopefilter_status`.
    ScopeFilterStatus: "scopefilterstatus" {
        InScope = "in_scope",
        OutScopeAs = "out_scope_as",
        OutScopePrefix = "out_scope_prefix",
    }
);

pg_enum!(
    /// `rpsl_objects.route_preference_status`.
    RoutePreferenceStatus: "routepreferencestatus" {
        Visible = "visible",
        Suppressed = "suppressed",
    }
);

pg_enum!(
    /// `rpsl_database_journal.operation`.
    DatabaseOperation: "databaseoperation" {
        AddOrUpdate = "add_or_update",
        Delete = "delete",
    }
);

pg_enum!(
    /// `rpsl_database_journal.origin`. `bogon_status` is a label left in the
    /// type by the migration that renamed it to `scope_filter`; v4 4.5 never
    /// writes it, but old journals can still hold it.
    JournalEntryOrigin: "journalentryorigin" {
        Unknown = "unknown",
        Mirror = "mirror",
        SyntheticNrtm = "synthetic_nrtm",
        PseudoIrr = "pseudo_irr",
        AuthChange = "auth_change",
        RpkiStatus = "rpki_status",
        BogonStatus = "bogon_status",
        ScopeFilter = "scope_filter",
        Suspension = "suspension",
        RoutePreference = "route_preference",
    }
);

pg_enum!(
    /// `change_log.rpsl_target_request_type`.
    UpdateRequestType: "updaterequesttype" {
        Create = "CREATE",
        Modify = "MODIFY",
        Delete = "DELETE",
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_render_in_utc_with_microseconds() {
        assert_eq!(Timestamp(0).to_string(), "1970-01-01T00:00:00.000000Z");
        assert_eq!(
            Timestamp(1_793_406_381_624_268).to_string(),
            "2026-10-31T00:39:41.624268Z"
        );
        assert_eq!(Timestamp(-1).to_string(), "1969-12-31T23:59:59.999999Z");
        assert_eq!(
            Timestamp(951_782_400_000_000).to_string(),
            "2000-02-29T00:00:00.000000Z"
        );
    }

    #[test]
    fn timestamp_decodes_postgres_epoch() {
        let ts = Timestamp::from_sql(&Type::TIMESTAMPTZ, &0i64.to_be_bytes()).unwrap();
        assert_eq!(ts.to_string(), "2000-01-01T00:00:00.000000Z");
        assert!(Timestamp::from_sql(&Type::TIMESTAMPTZ, &i64::MAX.to_be_bytes()).is_err());
    }

    #[test]
    fn inet_renders_like_postgres() {
        let host = Inet::from_sql(&Type::INET, &[2, 32, 0, 4, 192, 0, 2, 1]).unwrap();
        assert_eq!(host.to_string(), "192.0.2.1");
        let net = Inet::from_sql(&Type::INET, &[2, 24, 0, 4, 192, 0, 2, 0]).unwrap();
        assert_eq!(net.to_string(), "192.0.2.0/24");
        let cidr_host = Inet::from_sql(&Type::CIDR, &[2, 32, 1, 4, 192, 0, 2, 1]).unwrap();
        assert_eq!(cidr_host.to_string(), "192.0.2.1/32");
        let mut v6 = vec![3, 29, 1, 16, 0x20, 0x01, 0x13, 0xb0];
        v6.extend([0; 12]);
        assert_eq!(
            Inet::from_sql(&Type::CIDR, &v6).unwrap().to_string(),
            "2001:13b0::/29"
        );
        assert!(Inet::from_sql(&Type::INET, &[2, 33, 0, 4, 1, 2, 3, 4]).is_err());
        assert!(Inet::from_sql(&Type::INET, &[2, 32, 0, 4, 1, 2, 3]).is_err());
    }

    #[test]
    fn enum_labels_round_trip() {
        for o in ["unknown", "bogon_status", "route_preference"] {
            assert_eq!(JournalEntryOrigin::from_label(o).unwrap().label(), o);
        }
        assert!(RpkiStatus::from_label("NOT_FOUND").is_none());
    }

    #[test]
    fn ip_size_parses_beyond_u64() {
        assert_eq!(
            parse_numeric_u128("633825300114114700748351602688").unwrap(),
            633_825_300_114_114_700_748_351_602_688
        );
        assert!(parse_numeric_u128("1.5").is_err());
    }
}
