//! Maintainer auth, PGP, submissions and notifications: a port of v4's
//! `irrd/updates` package and `irrd/utils/{email,pgp}.py`.
//!
//! - [`handler::process`] runs a submission (an e-mail body, a
//!   `/v1/submit/` or a `/v1/suspension/` request) in one store write
//!   transaction and returns a [`handler::Handler`] for the reports.
//! - [`email`] is `irrd_submit_email`'s `handle_email_submission`, with
//!   [`email_parser`] for Python's MIME parsing and PGP checks.
//! - [`api`] validates `/v1/submit/` and `/v1/suspension/` request bodies
//!   with pydantic's error texts.

#![deny(unsafe_code)]

pub mod api;
mod charsets;
mod difflib;
pub mod email;
pub mod email_parser;
pub mod handler;
pub mod json;
pub mod messages;
pub mod meta;
mod request;
pub mod settings;
mod store_util;
mod suspension;
mod validators;

pub use handler::{ChangeObject, Handler, Submission, process};
pub use meta::RequestMeta;
pub use request::SuspensionType;
pub use settings::{AutnumAuthMode, SourceSubmitSettings, SubmitSettings};

use rpsl::{RpslObject, Value};
use store::{
    IpPrefix, Json, NewRpslObject, RoutePreferenceStatus, RpkiStatus, ScopeFilterStatus, Timestamp,
    WriteTx,
};

/// `META_KEY_HTTP_CLIENT_IP`
pub const META_KEY_HTTP_CLIENT_IP: &str = "HTTP-Client-IP";

/// An exception v4 does not handle where it happens: the submission as a
/// whole fails (an e-mail gets the internal error reply, an HTTP request
/// a 500). The text is the exception's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Internal(pub String);

impl From<store::StoreError> for Internal {
    fn from(e: store::StoreError) -> Self {
        Internal(e.to_string())
    }
}

/// `UpdateRequestStatus`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// `saved`
    Saved,
    /// `processing`
    Processing,
    /// `error: unknown RPSL class`
    ErrorUnknownClass,
    /// `errors encountered during object parsing`
    ErrorParsing,
    /// `error: update not authorised`
    ErrorAuth,
    /// `error: other rules not met`
    ErrorRules,
    /// `error: reference to object that does not exist`
    ErrorReference,
    /// `error: creation of an object under a protected name`
    ErrorProtectedName,
    /// `error: conflict with existing ROA`
    ErrorRoa,
    /// `error: not in scope`
    ErrorScopefilter,
    /// `error: attempt to update object in non-authoritive database`
    ErrorNonAuthoritive,
    /// `error: objects rejected due to object_class_filter setting`
    ErrorObjectFilter,
}

/// `AuthMethod`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthMethod {
    /// `OVERRIDE_PASSWORD`
    OverridePassword,
    /// `OVERRIDE_INTERNAL_AUTH`
    OverrideInternalAuth,
    /// `MNTNER_PASSWORD`
    MntnerPassword,
    /// `MNTNER_PGP_KEY`
    MntnerPgpKey,
    /// `MNTNER_INTERNAL_AUTH`
    MntnerInternalAuth,
    /// `MNTNER_API_KEY`
    MntnerApiKey,
    /// `MNTNER_IN_SAME_REQUEST`
    MntnerInSameRequest,
    /// `NONE`
    #[default]
    None,
}

impl AuthMethod {
    /// `used_override()`
    pub fn used_override(self) -> bool {
        matches!(
            self,
            AuthMethod::OverridePassword | AuthMethod::OverrideInternalAuth
        )
    }
}

/// `AuthoritativeChangeOrigin`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// `WEBAPI`
    WebApi,
    /// `EMAIL`
    Email,
    /// `OTHER`
    Other,
}

/// `uuid.UUID(text)`: hyphens and braces optional, `urn:uuid:` prefix
/// allowed, any case.
pub fn py_uuid(text: &str) -> Option<store::Uuid> {
    let mut hex = text.trim_matches(|c| c == '{' || c == '}').to_owned();
    if let Some(rest) = hex
        .strip_prefix("urn:")
        .or_else(|| hex.strip_prefix("URN:"))
    {
        hex = rest.to_owned();
    }
    if let Some(rest) = hex
        .strip_prefix("uuid:")
        .or_else(|| hex.strip_prefix("UUID:"))
    {
        hex = rest.to_owned();
    }
    let hex = hex.replace('-', "");
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    store::Uuid::parse_str(&hex).ok()
}

/// `parsed_data` as stored JSON.
pub(crate) fn parsed_data_json(obj: &RpslObject) -> Json {
    let mut map = serde_json::Map::new();
    for (k, v) in obj.parsed_data() {
        let jv = match v {
            Value::Str(s) => serde_json::Value::String(s.clone()),
            Value::List(l) => serde_json::Value::Array(
                l.iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        };
        map.insert((*k).to_owned(), jv);
    }
    Json::from_value(&serde_json::Value::Object(map))
}

/// The row `upsert_rpsl_object()` writes for an object: the text rendered
/// with a new `last-modified` (now), and the statuses as given; v4's
/// change requests leave them at `RPSLObject`'s defaults.
pub(crate) fn new_object(
    obj: &RpslObject,
    rpsl: &rpsl::RpslSettings,
    rpki: Option<RpkiStatus>,
    scope: Option<ScopeFilterStatus>,
) -> Result<NewRpslObject, Internal> {
    let source = obj
        .source()
        .map_err(|e| Internal(e.to_string()))?
        .to_owned();
    let prefix: Option<IpPrefix> = obj.prefix.as_ref().and_then(store_util::store_prefix);
    Ok(NewRpslObject {
        rpsl_pk: obj.pk(),
        object_class: obj.rpsl_object_class().to_owned(),
        parsed_data: parsed_data_json(obj),
        object_text: obj.render_rpsl_text_with_last_modified(Timestamp::now().unix_seconds(), rpsl),
        ip_first: obj.ip_first.as_ref().map(store_util::ip_of),
        ip_last: obj.ip_last.as_ref().map(store_util::ip_of),
        prefix,
        prefix_length: obj.prefix_length,
        asn_first: obj.asn_first,
        asn_last: obj.asn_last,
        rpki_status: rpki.unwrap_or(RpkiStatus::NotFound),
        scopefilter_status: scope.unwrap_or(ScopeFilterStatus::InScope),
        route_preference_status: RoutePreferenceStatus::Visible,
        source,
    })
}

/// `ScopeFilterValidator.validate_rpsl_object(obj)`: the status and v4's
/// explanation.
pub(crate) fn scope_status(
    settings: &SubmitSettings,
    obj: &RpslObject,
) -> Result<(ScopeFilterStatus, String), Internal> {
    if !matches!(obj.rpsl_object_class(), "route" | "route6" | "aut-num") {
        return Ok((ScopeFilterStatus::InScope, String::new()));
    }
    let v = rpki::ScopeFilterValidator::new(settings.scopefilter.clone());
    let source = store_util::source_of(obj)?;
    if let Some(p) = &obj.prefix
        && let Some(sp) = store_util::store_prefix(p)
    {
        let s = v.validate(&source, Some(&sp), None);
        if s != ScopeFilterStatus::InScope {
            return Ok((s, messages::prefix_out_of_scope(&p.to_string())));
        }
    }
    if let Some(asn) = obj.asn_first {
        let s = v.validate(&source, None, Some(asn));
        if s != ScopeFilterStatus::InScope {
            return Ok((s, messages::asn_out_of_scope(asn)));
        }
    }
    Ok((ScopeFilterStatus::InScope, String::new()))
}

/// `str.format(sources_str=...)` on `email.notification_header`. Any other
/// replacement field raises `KeyError` in v4.
pub(crate) fn format_sources_str(template: &str, sources_str: &str) -> Result<String, Internal> {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let mut field = String::new();
                for f in chars.by_ref() {
                    if f == '}' {
                        break;
                    }
                    field.push(f);
                }
                if field == "sources_str" {
                    out.push_str(sources_str);
                } else {
                    return Err(Internal(format!("'{field}'")));
                }
            }
            '}' => {
                return Err(Internal(
                    "Single '}' encountered in format string".to_owned(),
                ));
            }
            c => out.push(c),
        }
    }
    Ok(out)
}

/// v4's `send_email()`: a refused recipient is logged and skipped, a
/// delivery failure raises.
pub fn send_email(
    settings: &mail::MailSettings,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<(), Internal> {
    match mail::send_email(settings, recipient, subject, body) {
        Ok(()) | Err(mail::MailError::BadRecipient) => Ok(()),
        Err(mail::MailError::Delivery(m)) => Err(Internal(m)),
    }
}

/// The keyring as stored, for a write transaction.
pub(crate) fn load_keyring_tx(tx: &mut WriteTx<'_, '_>) -> Result<rpsl::Keyring, Internal> {
    Ok(rpsl::Keyring::from_entries(tx.read()?.pgp_keyring()?))
}
