//! NRTMv3 serving for `-g`: `NRTMGenerator.generate()`
//! (`irrd/mirroring/nrtm_generator.py`).

use std::fmt::Write as _;

use store::ReadView;

use crate::messages;
use crate::resolver::{QResult, QueryError, QueryResolver, invalid};
use crate::settings::{ConfigValue, QuerySettings};

/// One `-g` request, after parsing and the access check.
#[derive(Debug, Clone)]
pub struct NrtmRequest<'a> {
    /// Source, upper case.
    pub source: &'a str,
    /// `"1"` or `"3"`.
    pub version: &'a str,
    /// First serial requested.
    pub serial_start: i64,
    /// Last serial requested, `None` for `LAST`.
    pub serial_end: Option<i64>,
    /// Filter password hashes (client not in the unfiltered list).
    pub remove_auth_hashes: bool,
    /// Client is in the unfiltered list.
    pub client_is_dummifying_exempt: bool,
}

/// The journal stream of an NRTMv3 response, from the optional header to
/// `%END`. Called once the request has passed v4's serial range checks.
pub trait NrtmV3: Send + Sync {
    /// The response text, or the `NRTMGeneratorException` text. An empty
    /// error is an internal error.
    fn stream(
        &self,
        settings: &QuerySettings,
        view: &ReadView<'_>,
        request: &NrtmRequest<'_>,
        serial_end_display: i64,
    ) -> Result<String, String>;
}

/// NRTMv3 serving from the store's journal: the rest of
/// `NRTMGenerator.generate()` (`irrd/mirroring/nrtm_generator.py`).
#[derive(Debug, Clone, Copy, Default)]
pub struct NrtmServer;

/// `int(value)` of a setting, `None` where Python raises.
fn py_int(v: &ConfigValue) -> Option<i128> {
    match v {
        ConfigValue::Int(i) => Some(*i),
        ConfigValue::Bool(b) => Some(i128::from(*b)),
        ConfigValue::Float(f) if f.is_finite() => Some(f.trunc() as i128),
        ConfigValue::Str(s) => rpsl::python::int(s),
        _ => None,
    }
}

/// `str(value)` of a setting, for the error texts.
fn py_str(v: &ConfigValue) -> String {
    match v {
        ConfigValue::Null => "None".to_owned(),
        ConfigValue::Bool(true) => "True".to_owned(),
        ConfigValue::Bool(false) => "False".to_owned(),
        ConfigValue::Int(i) => i.to_string(),
        ConfigValue::Float(f) => format!("{f:?}"),
        ConfigValue::Str(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

/// `timedelta(days=value)` in microseconds, `None` where Python raises.
fn days_micros(v: &ConfigValue) -> Option<i128> {
    const DAY: f64 = 86_400_000_000.0;
    match v {
        ConfigValue::Int(i) => i.checked_mul(86_400_000_000),
        ConfigValue::Bool(b) => Some(i128::from(*b) * 86_400_000_000),
        ConfigValue::Float(f) if f.is_finite() => Some((f * DAY).round() as i128),
        _ => None,
    }
}

impl NrtmV3 for NrtmServer {
    fn stream(
        &self,
        settings: &QuerySettings,
        view: &ReadView<'_>,
        r: &NrtmRequest<'_>,
        serial_end_display: i64,
    ) -> Result<String, String> {
        let s = settings.source(r.source);
        let range_limit = &s.nrtm_query_serial_range_limit;
        if range_limit.truthy() {
            let limit = py_int(range_limit).ok_or_else(String::new)?;
            if limit < i128::from(serial_end_display) - i128::from(r.serial_start) {
                return Err(messages::nrtm_range_exceeded(&py_str(range_limit)));
            }
        }
        let days_limit = &s.nrtm_query_serial_days_limit;
        if days_limit.truthy() {
            let first = view
                .journal(Some(r.source), Some(r.serial_start), None)
                .map_err(|_| String::new())?
                .next()
                .transpose()
                .map_err(|_| String::new())?;
            let Some(first) = first else {
                return Err(messages::nrtm_no_entries_from(r.serial_start));
            };
            let limit = days_micros(days_limit).ok_or_else(String::new)?;
            let age = i128::from(store::Timestamp::now().0) - i128::from(first.timestamp.0);
            if age > limit {
                return Err(messages::nrtm_too_old(&py_str(days_limit)));
            }
        }

        let mut out = String::new();
        if let Some(header) = &s.nrtm_response_header {
            out.push_str(&rpsl::text::py_textwrap_indent(header, "%"));
            out.push('\n');
        }
        let _ = writeln!(
            out,
            "%START Version: {} {} {}-{}",
            r.version, r.source, r.serial_start, serial_end_display
        );
        let entries = view
            .journal(Some(r.source), Some(r.serial_start), r.serial_end)
            .map_err(|_| String::new())?;
        for entry in entries {
            let entry = entry.map_err(|_| String::new())?;
            out.push('\n');
            out.push_str(entry.operation.py_value());
            if r.version == "3" {
                let _ = write!(out, " {}", entry.serial_nrtm);
            }
            out.push_str("\n\n");
            let text = if r.remove_auth_hashes {
                rpsl::text::remove_auth_hashes(entry.object_text)
            } else {
                std::borrow::Cow::Borrowed(entry.object_text)
            };
            if r.client_is_dummifying_exempt {
                out.push_str(&text);
            } else {
                out.push_str(&rpsl::text::dummify_object_text(
                    &text,
                    entry.object_class,
                    entry.rpsl_pk,
                    &s.dummify,
                ));
            }
        }
        out.push('\n');
        out.push_str("%END ");
        out.push_str(r.source);
        Ok(out)
    }
}

/// `NRTMGenerator.generate()`: the checks that need only the settings
/// and `database_status`, then the stream.
pub(crate) fn generate(
    hook: &dyn NrtmV3,
    settings: &QuerySettings,
    view: &ReadView<'_>,
    r: &NrtmRequest<'_>,
) -> QResult<String> {
    if !settings.source(r.source).keep_journal.truthy() {
        return invalid(messages::NRTM_NO_JOURNAL.to_owned());
    }
    let Some(status) = QueryResolver::status_rows(view, &[r.source.to_owned()])?
        .into_iter()
        .next()
    else {
        return invalid(messages::NRTM_NO_ENTRIES.to_owned());
    };
    if let Some(end) = r.serial_end
        && end != 0
        && end < r.serial_start
    {
        return invalid(messages::nrtm_start_after_end(r.serial_start, end));
    }
    let (Some(start_available), Some(end_available)) =
        (status.serial_oldest_journal, status.serial_newest_journal)
    else {
        return Ok(messages::NRTM_NO_UPDATES.to_owned());
    };
    if r.serial_start < start_available {
        return invalid(messages::nrtm_serials_missing(
            r.serial_start,
            start_available,
        ));
    }
    if let Some(end) = r.serial_end
        && end > end_available
    {
        return invalid(messages::nrtm_serials_missing(end_available, end));
    }
    if r.serial_end.is_none() {
        if Some(r.serial_start) == end_available.checked_add(1) {
            return Ok(messages::NRTM_NO_NEWER_UPDATES.to_owned());
        } else if r.serial_start > end_available {
            return invalid(messages::nrtm_serials_missing(
                end_available,
                r.serial_start,
            ));
        }
    }
    let display = r.serial_end.unwrap_or(end_available);
    match hook.stream(settings, view, r, display) {
        Ok(text) => Ok(text),
        Err(e) if e.is_empty() => Err(QueryError::Internal(
            "NRTMv3 stream generation failed".to_owned(),
        )),
        Err(e) => invalid(e),
    }
}
