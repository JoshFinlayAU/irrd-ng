//! NRTMv3 serving for `-g`: the request checks of
//! `NRTMGenerator.generate()` (`irrd/mirroring/nrtm_generator.py`) that
//! only need the source's settings and `database_status`, and a hook for
//! the journal stream itself, which Phase 6 implements.

use store::ReadView;

use crate::messages;
use crate::resolver::{QResult, QueryError, QueryResolver, invalid};
use crate::settings::QuerySettings;

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

/// The journal stream of an NRTMv3 response, from the `%START` line to
/// `%END`. Called once the request has passed v4's serial range checks.
pub trait NrtmV3: Send + Sync {
    /// The response text, or the `NRTMGeneratorException` text.
    fn stream(
        &self,
        settings: &QuerySettings,
        view: &ReadView<'_>,
        request: &NrtmRequest<'_>,
        serial_end_display: i64,
    ) -> Result<String, String>;
}

/// Phase 3 placeholder: NRTMv3 serving is not built yet. Requests that get
/// past the checks v4 makes before reading the journal are answered with
/// v4's internal error.
#[derive(Debug, Clone, Copy, Default)]
pub struct NrtmNotServed;

impl NrtmV3 for NrtmNotServed {
    fn stream(
        &self,
        _: &QuerySettings,
        _: &ReadView<'_>,
        _: &NrtmRequest<'_>,
        _: i64,
    ) -> Result<String, String> {
        Err(String::new())
    }
}

/// `NRTMGenerator.generate()` up to the journal read, then the hook.
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
        if r.serial_start == end_available + 1 {
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
            "NRTMv3 serving is not available in this build".to_owned(),
        )),
        Err(e) => invalid(e),
    }
}
