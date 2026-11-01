//! `/v1/submit/` and `/v1/suspension/` (`ObjectSubmissionEndpoint` and
//! `SuspensionSubmissionEndpoint` in `irrd/server/http/endpoints_api.py`).

use std::sync::Arc;

use auth::api::{self, BodyError};
use auth::json::PyJson;
use auth::{RequestMeta, SubmitSettings};
use hyper::HeaderMap;
use store::Store;

/// What the endpoint answers.
pub(crate) enum SubmitReply {
    /// 200 with a JSON body.
    Json(String),
    /// 400 with a plain text body.
    BadRequest(String),
    /// An exception the endpoint does not catch: Starlette's 500.
    Internal(String),
}

fn header<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h [u8]> {
    headers.get(name).map(|v| v.as_bytes())
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// `ObjectSubmissionEndpoint._handle_submission(request, delete)`
pub(crate) fn submit(
    store: &Store,
    settings: Arc<SubmitSettings>,
    host: &str,
    headers: &HeaderMap,
    body: &[u8],
    delete: bool,
) -> SubmitReply {
    let data = match api::json_loads(body).and_then(|v| api::validate_change_submission(&v)) {
        Ok(d) => d,
        Err(BodyError::BadRequest(m)) => return SubmitReply::BadRequest(m),
        Err(BodyError::Internal(m)) => return SubmitReply::Internal(m),
    };
    let mut meta = match api::parse_metadata_header(header(headers, "x-irrd-metadata")) {
        Ok(m) => RequestMeta(m),
        Err(BodyError::Internal(m) | BodyError::BadRequest(m)) => return SubmitReply::Internal(m),
    };
    meta.set(auth::META_KEY_HTTP_CLIENT_IP, PyJson::Str(host.to_owned()));
    meta.set(
        "HTTP-User-Agent",
        header(headers, "user-agent").map_or(PyJson::Null, |v| PyJson::Str(latin1(v))),
    );
    let submission = data.into_submission(delete, Some(host.to_owned()));
    let mut handler = match auth::process(store, settings, submission, meta) {
        Ok(h) => h,
        Err(e) => return SubmitReply::Internal(e.0),
    };
    if let Err(e) = handler.send_notification_target_reports() {
        return SubmitReply::Internal(e.0);
    }
    SubmitReply::Json(handler.submitter_report_json())
}

/// `SuspensionSubmissionEndpoint.post(request)`
pub(crate) fn suspension(
    store: &Store,
    settings: Arc<SubmitSettings>,
    host: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> SubmitReply {
    let submission =
        match api::json_loads(body).and_then(|v| api::validate_suspension_submission(&v)) {
            Ok(s) => s,
            Err(BodyError::BadRequest(m)) => return SubmitReply::BadRequest(m),
            Err(BodyError::Internal(m)) => return SubmitReply::Internal(m),
        };
    let mut meta = RequestMeta::default();
    meta.set(auth::META_KEY_HTTP_CLIENT_IP, PyJson::Str(host.to_owned()));
    meta.set(
        "HTTP-User-Agent",
        header(headers, "user-agent").map_or(PyJson::Null, |v| PyJson::Str(latin1(v))),
    );
    match auth::process(store, settings, submission, meta) {
        Ok(mut h) => SubmitReply::Json(h.submitter_report_json()),
        Err(e) => SubmitReply::Internal(e.0),
    }
}
