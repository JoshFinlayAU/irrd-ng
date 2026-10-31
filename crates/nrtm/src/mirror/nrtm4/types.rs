//! `irrd/mirroring/nrtm4/nrtm4_types.py`: the Update Notification File and
//! the snapshot and delta headers, validated as v4's pydantic models do.
//!
//! Errors are formatted as v4's `format_pydantic_errors` joins them
//! (`loc->path: message`, then `; `), with pydantic's messages for the
//! cases that occur in practice.

use config::Value;
use uuid::Uuid;

use crate::messages;
use crate::mirror::nrtm4::json;
use crate::mirror::pyerr::PyErr;

/// `NRTM4FileReference`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReference {
    /// `version`
    pub version: i64,
    /// `url`
    pub url: String,
    /// `hash`
    pub hash: String,
}

/// UPDATE_NOTIFICATION_FILENAME.
pub const UPDATE_NOTIFICATION_FILENAME: &str = "update-notification-file.jose";

impl FileReference {
    /// `full_url(unf_url)`: the UNF's scheme and host name (no port, no
    /// user), with the UNF file name in its path replaced by this
    /// reference's `url`.
    pub fn full_url(&self, unf_url: &str) -> String {
        let parts = crate::mirror::retrieval::urlparse(unf_url);
        let host = hostname(&parts.netloc);
        let path = parts.path.replace(UPDATE_NOTIFICATION_FILENAME, &self.url);
        // urlunparse((scheme, hostname, path, "", "", ""))
        let mut out = String::new();
        if !parts.scheme.is_empty() {
            out.push_str(&parts.scheme);
            out.push(':');
        }
        let uses_netloc = matches!(
            parts.scheme.as_str(),
            "" | "ftp"
                | "http"
                | "https"
                | "file"
                | "gopher"
                | "nntp"
                | "telnet"
                | "imap"
                | "wais"
                | "mms"
                | "shttp"
                | "snews"
                | "prospero"
                | "rtsp"
                | "rtsps"
                | "rtspu"
                | "rsync"
                | "svn"
                | "svn+ssh"
                | "sftp"
                | "nfs"
                | "git"
                | "git+ssh"
                | "ws"
                | "wss"
                | "itms-services"
        );
        if !host.is_empty() || (!parts.scheme.is_empty() && uses_netloc && !path.starts_with("//"))
        {
            out.push_str("//");
            out.push_str(&host);
            if !path.is_empty() && !path.starts_with('/') {
                out.push('/');
            }
        }
        out.push_str(&path);
        out
    }
}

/// `urlparse(url).hostname`: lower case, without user info, port or IPv6
/// brackets.
fn hostname(netloc: &str) -> String {
    let hostport = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
    let host = if let Some(v6) = hostport.strip_prefix('[') {
        v6.split(']').next().unwrap_or_default()
    } else {
        hostport.split(':').next().unwrap_or_default()
    };
    host.to_lowercase()
}

/// An aware `datetime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    /// Microseconds since the epoch, UTC.
    pub unix_micros: i64,
    /// UTC offset in seconds.
    pub offset: i32,
}

impl DateTime {
    /// `isoformat()`.
    pub fn isoformat(&self) -> String {
        let local = self.unix_micros + i64::from(self.offset) * 1_000_000;
        let secs = local.div_euclid(1_000_000);
        let micros = local.rem_euclid(1_000_000);
        let days = secs.div_euclid(86_400);
        let sod = secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        let mut s = format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
            sod / 3600,
            (sod / 60) % 60,
            sod % 60
        );
        if micros != 0 {
            s.push_str(&format!(".{micros:06}"));
        }
        let sign = if self.offset < 0 { '-' } else { '+' };
        let o = self.offset.unsigned_abs();
        s.push_str(&format!("{sign}{:02}:{:02}", o / 3600, (o / 60) % 60));
        if !o.is_multiple_of(60) {
            s.push_str(&format!(":{:02}", o % 60));
        }
        s
    }
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The UNF `timestamp`: aware, or naive (which v4's validator cannot
/// subtract from an aware `now()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timestamp {
    /// With a time zone.
    Aware(DateTime),
    /// Without one.
    Naive,
}

/// pydantic's datetime parsing (speedate), for the forms that occur.
fn parse_datetime(s: &str) -> Result<Timestamp, String> {
    let b = s.as_bytes();
    if b.len() < 10 {
        return Err("input is too short".into());
    }
    let num = |r: std::ops::Range<usize>, what: &str| -> Result<i64, String> {
        let part = b.get(r).ok_or_else(|| "input is too short".to_owned())?;
        if !part.iter().all(u8::is_ascii_digit) {
            return Err(format!("invalid character in {what}"));
        }
        Ok(part.iter().fold(0i64, |a, c| a * 10 + i64::from(c - b'0')))
    };
    let year = num(0..4, "year")?;
    if b[4] != b'-' {
        return Err("invalid date separator, expected `-`".into());
    }
    let month = num(5..7, "month")?;
    if b[7] != b'-' {
        return Err("invalid date separator, expected `-`".into());
    }
    let day = num(8..10, "day")?;
    if !(1..=12).contains(&month) {
        return Err("month value is outside expected range of 1-12".into());
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let mdays = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day < 1 || day > mdays[(month - 1) as usize] {
        return Err("day value is outside expected range".into());
    }
    let days = days_from_civil(year, month, day);
    if b.len() == 10 {
        return Ok(Timestamp::Naive);
    }
    if !matches!(b[10], b'T' | b't' | b' ' | b'_') {
        return Err("invalid datetime separator, expected `T`, `t`, `_` or space".into());
    }
    let hour = num(11..13, "hour")?;
    if b.get(13) != Some(&b':') {
        return Err("invalid time separator, expected `:`".into());
    }
    let minute = num(14..16, "minute")?;
    let mut i = 16;
    let mut second = 0;
    let mut micros = 0i64;
    if b.get(i) == Some(&b':') {
        second = num(17..19, "second")?;
        i = 19;
        if matches!(b.get(i), Some(b'.') | Some(b',')) {
            i += 1;
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i == start {
                return Err("second fraction value is more than 6 digits long".into());
            }
            let frac = &s[start..i.min(start + 6)];
            micros = frac.parse::<i64>().unwrap_or(0) * 10i64.pow(6 - frac.len() as u32);
        }
    }
    if hour > 23 {
        return Err("hour value is outside expected range of 0-23".into());
    }
    if minute > 59 {
        return Err("minute value is outside expected range of 0-59".into());
    }
    if second > 59 {
        return Err("second value is outside expected range of 0-59".into());
    }
    let offset: Option<i32> = match b.get(i) {
        None => None,
        Some(b'Z') | Some(b'z') => {
            i += 1;
            Some(0)
        }
        Some(b'+') | Some(b'-') => {
            let sign = if b[i] == b'-' { -1 } else { 1 };
            let h = num(i + 1..i + 3, "timezone hour")?;
            i += 3;
            if b.get(i) == Some(&b':') {
                i += 1;
            }
            let m = num(i..i + 2, "timezone minute")?;
            i += 2;
            Some(sign * (h * 3600 + m * 60) as i32)
        }
        Some(_) => return Err("invalid timezone sign".into()),
    };
    if i != b.len() {
        return Err("unexpected extra characters at the end of the input".into());
    }
    let Some(offset) = offset else {
        return Ok(Timestamp::Naive);
    };
    let local = days * 86_400 + hour * 3600 + minute * 60 + second;
    Ok(Timestamp::Aware(DateTime {
        unix_micros: (local - i64::from(offset)) * 1_000_000 + micros,
        offset,
    }))
}

/// Field errors, as `(loc, message)`.
#[derive(Debug, Default)]
struct Errors(Vec<(String, String)>);

impl Errors {
    fn push(&mut self, loc: &str, msg: impl Into<String>) {
        self.0.push((loc.to_owned(), msg.into()));
    }

    fn joined(&self) -> String {
        self.0
            .iter()
            .map(|(l, m)| {
                if l.is_empty() {
                    m.clone()
                } else {
                    format!("{l}: {m}")
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// What failed, as v4's client sees it.
fn validation_error(errors: &Errors) -> PyErr {
    PyErr::Nrtm4(errors.joined())
}

const FIELD_REQUIRED: &str = "Field required";

fn v_str(errors: &mut Errors, loc: &str, v: Option<&Value>) -> Option<String> {
    match v {
        None => {
            errors.push(loc, FIELD_REQUIRED);
            None
        }
        Some(Value::Str(s)) => Some(s.clone()),
        Some(_) => {
            errors.push(loc, "Input should be a valid string");
            None
        }
    }
}

fn v_positive_int(errors: &mut Errors, loc: &str, v: Option<&Value>) -> Option<i64> {
    let n: i64 = match v {
        None => {
            errors.push(loc, FIELD_REQUIRED);
            return None;
        }
        Some(Value::Bool(b)) => i64::from(*b),
        Some(Value::Int(i)) => match i.to_string().parse() {
            Ok(n) => n,
            Err(_) => {
                errors.push(
                    loc,
                    "Input should be a valid integer, unable to parse number as an integer",
                );
                return None;
            }
        },
        Some(Value::Float(f)) => {
            if f.fract() != 0.0 || !f.is_finite() {
                errors.push(
                    loc,
                    "Input should be a valid integer, got a number with a fractional part",
                );
                return None;
            }
            *f as i64
        }
        Some(Value::Str(s)) => match rpsl::text::py_strip(s).parse::<i64>() {
            Ok(n) => n,
            Err(_) => {
                errors.push(
                    loc,
                    "Input should be a valid integer, unable to parse string as an integer",
                );
                return None;
            }
        },
        Some(_) => {
            errors.push(loc, "Input should be a valid integer");
            return None;
        }
    };
    if n <= 0 {
        errors.push(loc, "Input should be greater than 0");
        return None;
    }
    Some(n)
}

fn v_uuid(errors: &mut Errors, loc: &str, v: Option<&Value>) -> Option<Uuid> {
    match v {
        None => {
            errors.push(loc, FIELD_REQUIRED);
            None
        }
        Some(Value::Str(s)) => match Uuid::parse_str(s) {
            Ok(u) => Some(u),
            Err(_) => {
                errors.push(
                    loc,
                    format!("Input should be a valid UUID, {}", uuid_error(s)),
                );
                None
            }
        },
        Some(_) => {
            errors.push(loc, "UUID input should be a string, bytes or UUID object");
            None
        }
    }
}

/// The `uuid` crate's error message, as the version in pydantic-core
/// words it.
fn uuid_error(input: &str) -> String {
    let (s, offset, simple) =
        if let Some(r) = input.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
            (r, 1, false)
        } else if let Some(r) = input.strip_prefix("urn:uuid:") {
            (r, 9, false)
        } else {
            (input, 0, true)
        };
    let mut hyphens = 0;
    let mut bounds = [0usize; 4];
    for (i, c) in s.char_indices() {
        if c == '-' {
            if hyphens < 4 {
                bounds[hyphens] = i;
            }
            hyphens += 1;
        } else if !c.is_ascii_hexdigit() {
            return format!(
                "invalid character: expected an optional prefix of `urn:uuid:` followed by \
                 [0-9a-fA-F-], found `{c}` at {}",
                i + offset + 1
            );
        }
    }
    if hyphens == 0 && simple {
        return format!(
            "invalid length: expected length 32 for simple format, found {}",
            s.len()
        );
    }
    if hyphens != 4 {
        return format!("invalid group count: expected 5, found {}", hyphens + 1);
    }
    const STARTS: [usize; 5] = [0, 9, 14, 19, 24];
    const LENS: [usize; 5] = [8, 4, 4, 4, 12];
    for i in 0..4 {
        if bounds[i] != STARTS[i + 1] - 1 {
            return format!(
                "invalid group length in group {i}: expected {}, found {}",
                LENS[i],
                bounds[i].saturating_sub(STARTS[i])
            );
        }
    }
    format!(
        "invalid group length in group 4: expected 12, found {}",
        s.len().saturating_sub(STARTS[4])
    )
}

fn v_literal_int(errors: &mut Errors, loc: &str, v: Option<&Value>, want: i64) {
    match v {
        None => errors.push(loc, FIELD_REQUIRED),
        Some(Value::Int(i)) if i.to_string() == want.to_string() => {}
        Some(_) => errors.push(loc, format!("Input should be {want}")),
    }
}

fn v_literal_str(errors: &mut Errors, loc: &str, v: Option<&Value>, want: &str) {
    match v {
        None => errors.push(loc, FIELD_REQUIRED),
        Some(Value::Str(s)) if s == want => {}
        Some(_) => errors.push(loc, format!("Input should be '{want}'")),
    }
}

/// The fields of `NRTM4Common`.
struct Common {
    source: Option<String>,
    session_id: Option<Uuid>,
    version: Option<i64>,
}

fn v_common(errors: &mut Errors, d: &Value) -> Common {
    v_literal_int(errors, "nrtm_version", json::get(d, "nrtm_version"), 4);
    Common {
        source: v_str(errors, "source", json::get(d, "source")),
        session_id: v_uuid(errors, "session_id", json::get(d, "session_id")),
        version: v_positive_int(errors, "version", json::get(d, "version")),
    }
}

fn v_file_reference(errors: &mut Errors, loc: &str, v: Option<&Value>) -> Option<FileReference> {
    match v {
        None => {
            errors.push(loc, FIELD_REQUIRED);
            None
        }
        Some(d @ Value::Dict(_)) => {
            let version =
                v_positive_int(errors, &format!("{loc}->version"), json::get(d, "version"));
            let url = v_str(errors, &format!("{loc}->url"), json::get(d, "url"));
            let hash = v_str(errors, &format!("{loc}->hash"), json::get(d, "hash"));
            Some(FileReference {
                version: version?,
                url: url?,
                hash: hash?,
            })
        }
        Some(_) => {
            errors.push(loc, "Input should be an object");
            None
        }
    }
}

/// `NRTM4UpdateNotificationFile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unf {
    /// `source`
    pub source: String,
    /// `session_id`
    pub session_id: Uuid,
    /// `version`
    pub version: i64,
    /// `timestamp`
    pub timestamp: DateTime,
    /// `snapshot`
    pub snapshot: FileReference,
    /// `deltas`
    pub deltas: Vec<FileReference>,
    /// `next_signing_key`
    pub next_signing_key: Option<String>,
}

impl Unf {
    /// `min_delta_version`
    pub fn min_delta_version(&self) -> Option<i64> {
        self.deltas.first().map(|d| d.version)
    }

    /// `max_delta_version`
    pub fn max_delta_version(&self) -> Option<i64> {
        self.deltas.last().map(|d| d.version)
    }
}

fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

/// `NRTM4UpdateNotificationFile.model_validate_json(payload,
/// context={"expected_values": {"source": source}})`.
pub fn validate_unf(payload: &[u8], expected_source: &str) -> Result<Unf, PyErr> {
    validate_unf_at(payload, expected_source, now_micros())
}

/// [`validate_unf`] at a given time (microseconds since the epoch).
pub fn validate_unf_at(payload: &[u8], expected_source: &str, now: i64) -> Result<Unf, PyErr> {
    let mut errors = Errors::default();
    let d = match json::loads(payload) {
        Ok(d) => d,
        Err(e) => {
            errors.push("", format!("Invalid JSON: {e}"));
            return Err(validation_error(&errors));
        }
    };
    if !matches!(d, Value::Dict(_)) {
        errors.push("", "Input should be an object");
        return Err(validation_error(&errors));
    }
    let common = v_common(&mut errors, &d);
    let timestamp = match json::get(&d, "timestamp") {
        None => {
            errors.push("timestamp", FIELD_REQUIRED);
            None
        }
        Some(v) => {
            let parsed = match v {
                Value::Str(s) => parse_datetime(s)
                    .map_err(|e| format!("Input should be a valid datetime or date, {e}")),
                Value::Int(i) => i
                    .to_string()
                    .parse::<i64>()
                    .map(|n| {
                        let micros = if n.abs() > 20_000_000_000 {
                            n * 1000
                        } else {
                            n * 1_000_000
                        };
                        Timestamp::Aware(DateTime {
                            unix_micros: micros,
                            offset: 0,
                        })
                    })
                    .map_err(|_| "Input should be a valid datetime".to_owned()),
                Value::Float(f) => {
                    let micros = if f.abs() > 2e10 { f * 1e3 } else { f * 1e6 };
                    Ok(Timestamp::Aware(DateTime {
                        unix_micros: micros.round() as i64,
                        offset: 0,
                    }))
                }
                _ => Err("Input should be a valid datetime".to_owned()),
            };
            match parsed {
                Err(e) => {
                    errors.push("timestamp", e);
                    None
                }
                // validate_timestamp: an aware now() minus a naive value.
                Ok(Timestamp::Naive) => {
                    return Err(PyErr::Other(
                        "can't subtract offset-naive and offset-aware datetimes".into(),
                    ));
                }
                Ok(Timestamp::Aware(ts)) => {
                    if now - ts.unix_micros > 24 * 3600 * 1_000_000 {
                        errors.push(
                            "timestamp",
                            format!(
                                "Value error, {}",
                                messages::nrtm4_unf_too_old(&ts.isoformat())
                            ),
                        );
                        None
                    } else {
                        Some(ts)
                    }
                }
            }
        }
    };
    v_literal_str(&mut errors, "type", json::get(&d, "type"), "notification");
    let snapshot = v_file_reference(&mut errors, "snapshot", json::get(&d, "snapshot"));
    let deltas = match json::get(&d, "deltas") {
        None => {
            errors.push("deltas", FIELD_REQUIRED);
            None
        }
        Some(Value::List(items)) => {
            let mut out = Vec::new();
            let mut ok = true;
            for (i, item) in items.iter().enumerate() {
                match v_file_reference(&mut errors, &format!("deltas->{i}"), Some(item)) {
                    Some(r) => out.push(r),
                    None => ok = false,
                }
            }
            ok.then_some(out)
        }
        Some(_) => {
            errors.push("deltas", "Input should be a valid array");
            None
        }
    };
    let next_signing_key = match json::get(&d, "next_signing_key") {
        None | Some(Value::None) => Some(None),
        Some(Value::Str(k)) => {
            if k.is_empty() {
                Some(Some(k.clone()))
            } else {
                match config::eckey_check(k) {
                    Ok(()) => Some(Some(k.clone())),
                    Err(Ok(ve)) => {
                        errors.push(
                            "next_signing_key",
                            format!(
                                "Value error, {}",
                                messages::nrtm4_invalid_next_signing_key(k, &ve)
                            ),
                        );
                        None
                    }
                    Err(Err(e)) => return Err(PyErr::Other(e.message)),
                }
            }
        }
        Some(_) => {
            errors.push("next_signing_key", "Input should be a valid string");
            None
        }
    };
    if !errors.0.is_empty() {
        return Err(validation_error(&errors));
    }
    let (
        Some(source),
        Some(session_id),
        Some(version),
        Some(timestamp),
        Some(snapshot),
        Some(deltas),
        Some(next_signing_key),
    ) = (
        common.source,
        common.session_id,
        common.version,
        timestamp,
        snapshot,
        deltas,
        next_signing_key,
    )
    else {
        return Err(PyErr::Other("incomplete validation".into()));
    };
    // validate_expected_values (the mixin's validator runs first).
    if source != expected_source {
        errors.push(
            "",
            format!(
                "Value error, {}",
                messages::nrtm4_mismatch("source", expected_source, &source)
            ),
        );
        return Err(validation_error(&errors));
    }
    let unf = Unf {
        source,
        session_id,
        version,
        timestamp,
        snapshot,
        deltas,
        next_signing_key,
    };
    // check_version_consistency
    let mut expected = unf.snapshot.version;
    if let Some(max) = unf.max_delta_version() {
        expected = expected.max(max);
    }
    if unf.version != expected {
        errors.push(
            "",
            format!(
                "Value error, {}",
                messages::nrtm4_unf_version_inconsistent(unf.version, expected)
            ),
        );
        return Err(validation_error(&errors));
    }
    if let (Some(min), Some(max)) = (unf.min_delta_version(), unf.max_delta_version()) {
        let contiguous = unf.deltas.iter().map(|d| d.version).eq(min..=max);
        if !contiguous {
            errors.push(
                "",
                format!("Value error, {}", messages::NRTM4_DELTAS_NOT_CONTIGUOUS),
            );
            return Err(validation_error(&errors));
        }
    }
    Ok(unf)
}

/// A snapshot or delta header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// `session_id`
    pub session_id: Uuid,
    /// `version`
    pub version: i64,
    /// `origin_identifier`
    pub origin_identifier: String,
}

/// Which header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderKind {
    /// `NRTM4SnapshotHeader`
    Snapshot,
    /// `NRTM4DeltaHeader`
    Delta,
}

/// `NRTM4SnapshotHeader`/`NRTM4DeltaHeader.model_validate(item,
/// context={"expected_values": {source, session_id, version}})`.
pub fn validate_header(
    item: &Value,
    kind: HeaderKind,
    source: &str,
    session_id: &Uuid,
    version: i64,
) -> Result<Header, PyErr> {
    let mut errors = Errors::default();
    let (model, type_value) = match kind {
        HeaderKind::Snapshot => ("NRTM4SnapshotHeader", "snapshot"),
        HeaderKind::Delta => ("NRTM4DeltaHeader", "delta"),
    };
    if !matches!(item, Value::Dict(_)) {
        errors.push(
            "",
            format!("Input should be a valid dictionary or instance of {model}"),
        );
        return Err(validation_error(&errors));
    }
    let common = v_common(&mut errors, item);
    v_literal_str(&mut errors, "type", json::get(item, "type"), type_value);
    if !errors.0.is_empty() {
        return Err(validation_error(&errors));
    }
    let (Some(s), Some(sid), Some(v)) = (common.source, common.session_id, common.version) else {
        return Err(PyErr::Other("incomplete validation".into()));
    };
    let mismatch = if s != source {
        Some(messages::nrtm4_mismatch("source", source, &s))
    } else if sid != *session_id {
        Some(messages::nrtm4_mismatch(
            "session_id",
            &session_id.to_string(),
            &sid.to_string(),
        ))
    } else if v != version {
        Some(messages::nrtm4_mismatch(
            "version",
            &version.to_string(),
            &v.to_string(),
        ))
    } else {
        None
    };
    if let Some(m) = mismatch {
        errors.push("", format!("Value error, {m}"));
        return Err(validation_error(&errors));
    }
    let origin_identifier = match kind {
        HeaderKind::Snapshot => messages::nrtm4_snapshot_origin(&sid.to_string(), v),
        HeaderKind::Delta => messages::nrtm4_delta_origin(&sid.to_string(), v),
    };
    Ok(Header {
        session_id: sid,
        version: v,
        origin_identifier,
    })
}

#[cfg(test)]
mod tests {
    //! v4's `test_nrtm4_types.py`, plus the messages pydantic gives for
    //! the UNF mistakes recorded from the pinned v4.

    use super::*;

    const SESSION: &str = "ca128382-78d9-41d1-8927-1ecef15275be";

    fn unf_json(edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut v = serde_json::json!({
            "nrtm_version": 4, "source": "TEST", "session_id": SESSION, "version": 4,
            "type": "notification", "timestamp": "2022-03-15 00:00:00+00:00",
            "snapshot": {"version": 3, "url": "https://example.com/snapshot.2.json", "hash": "hash"},
            "deltas": [
                {"version": 2, "url": "https://example.com/delta.2.json", "hash": "hash"},
                {"version": 3, "url": "https://example.com/delta.3.json", "hash": "hash"},
                {"version": 4, "url": "https://example.com/delta.4.json", "hash": "hash"},
            ],
        });
        edit(&mut v);
        serde_json::to_vec(&v).expect("json")
    }

    // 2022-03-14T12:34:56Z
    const NOW: i64 = 1_647_261_296_000_000;

    fn err(p: &[u8]) -> String {
        match validate_unf_at(p, "TEST", NOW) {
            Err(PyErr::Nrtm4(m)) => m,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[test]
    fn valid() {
        let u = validate_unf_at(&unf_json(|_| {}), "TEST", NOW).expect("valid");
        assert_eq!(u.min_delta_version(), Some(2));
        assert_eq!(u.max_delta_version(), Some(4));
        let u = validate_unf_at(
            &unf_json(|v| {
                v["deltas"] = serde_json::json!([]);
                v["version"] = 3.into();
            }),
            "TEST",
            NOW,
        )
        .expect("valid");
        assert_eq!(u.min_delta_version(), None);
    }

    #[test]
    fn invalid_cases() {
        assert!(
            err(&unf_json(|v| {
                v.as_object_mut().expect("obj").remove("snapshot");
            }))
            .contains("snapshot: Field required")
        );
        assert!(
            err(&unf_json(|v| v["snapshot"]["version"] = 10.into()))
                .contains("version 4 should have ")
        );
        assert!(
            err(&unf_json(|v| {
                v["version"] = 1.into();
                v["snapshot"]["version"] = 1.into();
            }))
            .contains("version 1 should have ")
        );
        assert!(
            err(&unf_json(|v| {
                v["version"] = 5.into();
                v["deltas"][2]["version"] = 5.into();
            }))
            .contains("do not have contiguous serials")
        );
        assert_eq!(
            err(&unf_json(
                |v| v["timestamp"] = "2022-03-12 00:00:00+00:00".into()
            )),
            "timestamp: Value error, Update Notification File is older than 24 hours, timestamp 2022-03-12T00:00:00+00:00"
        );
        assert!(
            err(&unf_json(|v| v["next_signing_key"] = "invalid".into()))
                .contains("invalid next_signing_key")
        );
    }

    // Messages recorded from the pinned v4 (pydantic 2) for each mistake.
    #[test]
    fn pydantic_messages() {
        let now_ok = |e: &mut serde_json::Value| e["timestamp"] = "2022-03-14T12:00:00Z".into();
        type Edit = Box<dyn Fn(&mut serde_json::Value)>;
        let cases: Vec<(Edit, &str)> = vec![
            (
                Box::new(|v| v["nrtm_version"] = 3.into()),
                "nrtm_version: Input should be 4",
            ),
            (
                Box::new(|v| v["nrtm_version"] = "4".into()),
                "nrtm_version: Input should be 4",
            ),
            (
                Box::new(|v| v["source"] = "OTHER".into()),
                "Value error, Mismatch in source field: expected TEST, found OTHER",
            ),
            (
                Box::new(|v| v["source"] = 5.into()),
                "source: Input should be a valid string",
            ),
            (
                Box::new(|v| v["session_id"] = "nope".into()),
                "session_id: Input should be a valid UUID, invalid character: expected an optional prefix of `urn:uuid:` followed by [0-9a-fA-F-], found `n` at 1",
            ),
            (
                Box::new(|v| v["version"] = 0.into()),
                "version: Input should be greater than 0",
            ),
            (
                Box::new(|v| v["version"] = 4.5.into()),
                "version: Input should be a valid integer, got a number with a fractional part",
            ),
            (
                Box::new(|v| v["version"] = true.into()),
                "Value error, Update Notification File version 1 should have version 4 based on Snapshot and Delta versions",
            ),
            (
                Box::new(|v| v["type"] = "snapshot".into()),
                "type: Input should be 'notification'",
            ),
            (
                Box::new(|v| v["snapshot"] = serde_json::Value::Null),
                "snapshot: Input should be an object",
            ),
            (
                Box::new(|v| {
                    v["snapshot"] = serde_json::json!({"version": "x", "url": "u", "hash": "h"})
                }),
                "snapshot->version: Input should be a valid integer, unable to parse string as an integer",
            ),
            (
                Box::new(|v| v["snapshot"] = serde_json::json!({"version": 3})),
                "snapshot->url: Field required; snapshot->hash: Field required",
            ),
            (
                Box::new(|v| v["deltas"] = serde_json::json!({})),
                "deltas: Input should be a valid array",
            ),
            (
                Box::new(|v| v["deltas"] = serde_json::json!([5])),
                "deltas->0: Input should be an object",
            ),
            (
                Box::new(|v| v["timestamp"] = "yesterday".into()),
                "timestamp: Input should be a valid datetime or date, input is too short",
            ),
            (
                Box::new(|v| v["next_signing_key"] = 5.into()),
                "next_signing_key: Input should be a valid string",
            ),
            (
                Box::new(|v| v["version"] = 7.into()),
                "Value error, Update Notification File version 7 should have version 4 based on Snapshot and Delta versions",
            ),
            (
                Box::new(|v| {
                    v["nrtm_version"] = 3.into();
                    v.as_object_mut().expect("obj").remove("source");
                    v["version"] = 0.into();
                }),
                "nrtm_version: Input should be 4; source: Field required; version: Input should be greater than 0",
            ),
            (
                Box::new(|v| {
                    v["source"] = "X".into();
                    v["version"] = 7.into();
                }),
                "Value error, Mismatch in source field: expected TEST, found X",
            ),
        ];
        for (edit, want) in cases {
            let p = unf_json(|v| {
                now_ok(v);
                v["deltas"] = serde_json::json!([
                    {"version": 3, "url": "d3", "hash": "h"},
                    {"version": 4, "url": "d4", "hash": "h"}
                ]);
                edit(v);
            });
            assert_eq!(err(&p), want);
        }
        assert_eq!(
            err(b"{bad"),
            "Invalid JSON: key must be a string at line 1 column 2"
        );
        assert_eq!(err(b"[1]"), "Input should be an object");
        assert_eq!(
            err(b""),
            "Invalid JSON: EOF while parsing a value at line 1 column 0"
        );
        assert_eq!(
            validate_unf_at(
                &unf_json(|v| v["timestamp"] = "2026-10-31T00:00:00".into()),
                "TEST",
                NOW
            ),
            Err(PyErr::Other(
                "can't subtract offset-naive and offset-aware datetimes".into()
            ))
        );
        let p = unf_json(|v| v["timestamp"] = 1_647_200_000.into());
        assert_eq!(
            validate_unf_at(&p, "TEST", NOW)
                .expect("int timestamp")
                .timestamp
                .isoformat(),
            "2022-03-13T19:33:20+00:00"
        );
    }

    #[test]
    fn headers() {
        let sid = Uuid::parse_str(SESSION).expect("uuid");
        let h = |v: serde_json::Value| json::loads(&serde_json::to_vec(&v).expect("j")).expect("v");
        let ok = h(
            serde_json::json!({"nrtm_version": 4, "type": "snapshot", "source": "TEST", "session_id": SESSION, "version": 3}),
        );
        let got = validate_header(&ok, HeaderKind::Snapshot, "TEST", &sid, 3).expect("valid");
        assert_eq!(got.origin_identifier, format!("{SESSION}/S3"));
        let msg = |v, kind| match validate_header(&v, kind, "TEST", &sid, 3) {
            Err(PyErr::Nrtm4(m)) => m,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            msg(
                h(
                    serde_json::json!({"nrtm_version": 4, "type": "snapshot", "source": "TEST", "session_id": SESSION, "version": 4})
                ),
                HeaderKind::Snapshot
            ),
            "Value error, Mismatch in version field: expected 3, found 4"
        );
        assert_eq!(
            msg(
                h(
                    serde_json::json!({"nrtm_version": 4, "type": "snapshot", "source": "TEST", "session_id": "ca128382-78d9-41d1-8927-1ecef15275bf", "version": 3})
                ),
                HeaderKind::Snapshot
            ),
            "Value error, Mismatch in session_id field: expected ca128382-78d9-41d1-8927-1ecef15275be, found ca128382-78d9-41d1-8927-1ecef15275bf"
        );
        assert_eq!(
            msg(
                h(
                    serde_json::json!({"nrtm_version": 4, "type": "delta", "source": "TEST", "session_id": SESSION, "version": 3})
                ),
                HeaderKind::Snapshot
            ),
            "type: Input should be 'snapshot'"
        );
        assert_eq!(
            msg(h(serde_json::json!([1])), HeaderKind::Snapshot),
            "Input should be a valid dictionary or instance of NRTM4SnapshotHeader"
        );
        assert_eq!(
            msg(
                h(serde_json::json!({"type": "snapshot"})),
                HeaderKind::Snapshot
            ),
            "nrtm_version: Field required; source: Field required; session_id: Field required; version: Field required"
        );
        assert_eq!(
            msg(
                h(
                    serde_json::json!({"nrtm_version": 4, "type": "snapshot", "source": "TEST", "session_id": 5, "version": 3})
                ),
                HeaderKind::Snapshot
            ),
            "session_id: UUID input should be a string, bytes or UUID object"
        );
        let delta = h(
            serde_json::json!({"nrtm_version": 4, "type": "delta", "source": "TEST", "session_id": SESSION, "version": "3"}),
        );
        assert_eq!(
            validate_header(&delta, HeaderKind::Delta, "TEST", &sid, 3)
                .expect("lax int")
                .origin_identifier,
            format!("{SESSION}/D3")
        );
    }

    #[test]
    fn full_url_like_v4() {
        let r = FileReference {
            version: 1,
            url: "snapshot.2.json".into(),
            hash: "h".into(),
        };
        assert_eq!(
            r.full_url("https://User@Example.com:8443/x/update-notification-file.jose"),
            "https://example.com/x/snapshot.2.json"
        );
        assert_eq!(
            r.full_url("file:///srv/nrtm/update-notification-file.jose"),
            "file:///srv/nrtm/snapshot.2.json"
        );
    }
}
