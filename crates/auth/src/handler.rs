//! `irrd/updates/handler.py`: `ChangeSubmissionHandler`.
//!
//! The whole submission runs in one store write transaction, as v4 runs it
//! in one database transaction: parsing, the validation rounds, the saves
//! and the change log. The reports and notifications are produced from the
//! returned [`Handler`] afterwards, as v4 produces them after `commit()`.

use std::sync::Arc;

use rpsl::Keyring;
use store::{Store, UpdateRequestType, WriteTx};

use crate::meta::RequestMeta;
use crate::request::{ChangeRequest, Ctx, Request, SuspensionRequest, SuspensionType};
use crate::settings::SubmitSettings;
use crate::validators::{AuthValidator, ReferenceValidator};
use crate::{Internal, Origin, Status, messages};

/// v4's logger.
pub const LOG_TARGET: &str = "irrd.updates.handler";

/// One object of a `/v1/submit/` request (`RPSLChangeSubmissionObject`),
/// already turned into text.
#[derive(Debug, Clone)]
pub struct ChangeObject {
    /// `object_text`, or the attributes joined as `name: value` lines.
    pub text: String,
}

/// What to process.
#[derive(Debug, Clone)]
pub enum Submission {
    /// `load_text_blob`: an e-mail body or other text with meta attributes.
    TextBlob {
        /// The text.
        text: String,
        /// Where it came from.
        origin: Origin,
        /// The fingerprint of a valid PGP signature on it.
        pgp_fingerprint: Option<String>,
    },
    /// `load_change_submission`: a `/v1/submit/` request.
    Change {
        /// The objects.
        objects: Vec<ChangeObject>,
        /// `passwords`
        passwords: Vec<String>,
        /// `override`
        override_: Option<String>,
        /// `api_keys`
        api_keys: Vec<String>,
        /// `delete_reason`, for a DELETE request.
        delete_reason: Option<String>,
        /// The client address.
        remote_ip: Option<String>,
    },
    /// `load_suspension_submission`: a `/v1/suspension/` request, as
    /// (mntner, source, request type).
    Suspension {
        /// The objects.
        objects: Vec<(String, String, SuspensionType)>,
        /// `override`
        override_: Option<String>,
    },
}

/// The handler after processing: the requests, ready for reporting.
#[derive(Debug)]
pub struct Handler {
    results: Vec<Request>,
    auth: AuthValidator,
    meta: RequestMeta,
    settings: Arc<SubmitSettings>,
}

/// Process a submission in one write transaction. The PGP keys imported
/// while parsing key-cert objects are stored in the same transaction.
pub fn process(
    store: &Store,
    settings: Arc<SubmitSettings>,
    submission: Submission,
    meta: RequestMeta,
) -> Result<Handler, Internal> {
    let objects = submission_object_count(&submission);
    tracing::info!(target: LOG_TARGET, "Processing change requests for {objects} object(s), metadata is {}", meta.py_repr());
    // Large enough that the closure does not run twice for a map resize.
    let reserve = 64 << 20;
    let (handler, _) = store.write_reserving(reserve, move |tx| {
        let keyring = match crate::load_keyring_tx(tx) {
            Ok(k) => k,
            Err(e) => return Ok(Err(e)),
        };
        let r = run(
            tx,
            settings.clone(),
            submission.clone(),
            meta.clone(),
            &keyring,
        );
        for (fpr, bytes) in keyring.dirty_entries() {
            tx.put_pgp_key(&fpr, &bytes)?;
        }
        Ok(r)
    })?;
    handler
}

fn submission_object_count(s: &Submission) -> usize {
    match s {
        Submission::TextBlob { .. } => 0,
        Submission::Change { objects, .. } => objects.len(),
        Submission::Suspension { objects, .. } => objects.len(),
    }
}

fn run(
    tx: &mut WriteTx<'_, '_>,
    settings: Arc<SubmitSettings>,
    submission: Submission,
    meta: RequestMeta,
    keyring: &Keyring,
) -> Result<Handler, Internal> {
    let ctx = Ctx {
        settings: &settings,
        keyring,
        meta: &meta,
    };
    let mut refs = ReferenceValidator::default();
    let (mut auth, mut requests) = match submission {
        Submission::TextBlob {
            text,
            origin,
            pgp_fingerprint,
        } => {
            let key_id = match pgp_fingerprint {
                Some(f) => resolve_pgp_key_id(tx, &f, &meta)?,
                None => None,
            };
            let mut auth = AuthValidator::new(origin, key_id, None);
            let requests = crate::request::parse_change_requests(&text, tx, &ctx, &mut auth)?;
            (auth, requests)
        }
        Submission::Change {
            objects,
            passwords,
            override_,
            api_keys,
            delete_reason,
            remote_ip,
        } => {
            let remote = remote_ip.and_then(|h| rpsl::Ip::parse(&h, 0).ok());
            let mut auth = AuthValidator::new(Origin::WebApi, None, remote);
            auth.passwords = passwords;
            auth.overrides = override_.into_iter().filter(|o| !o.is_empty()).collect();
            auth.api_keys = api_keys;
            let mut requests = Vec::new();
            for o in objects {
                requests.push(Request::Change(Box::new(ChangeRequest::new(
                    &o.text,
                    tx,
                    &ctx,
                    delete_reason.as_deref(),
                )?)));
            }
            (auth, requests)
        }
        Submission::Suspension { objects, override_ } => {
            let mut auth = AuthValidator::new(Origin::Other, None, None);
            auth.overrides = override_.into_iter().filter(|o| !o.is_empty()).collect();
            let mut requests = Vec::new();
            for (mntner, source, t) in objects {
                let text = format!("mntner: {mntner}\nsource: {source}\n");
                requests.push(Request::Suspension(Box::new(SuspensionRequest::new(
                    &text,
                    &ctx,
                    t.value(),
                )?)));
            }
            (auth, requests)
        }
    };

    handle_change_requests(tx, &ctx, &mut requests, &mut refs, &mut auth)?;
    Ok(Handler {
        results: requests,
        auth,
        meta: meta.clone(),
        settings: settings.clone(),
    })
}

/// `_handle_change_requests`
fn handle_change_requests(
    tx: &mut WriteTx<'_, '_>,
    ctx: &Ctx<'_>,
    requests: &mut [Request],
    refs: &mut ReferenceValidator,
    auth: &mut AuthValidator,
) -> Result<(), Internal> {
    let valid_indices = |requests: &mut [Request], auth: &mut AuthValidator| -> Vec<usize> {
        let mut out = Vec::new();
        for (i, r) in requests.iter_mut().enumerate() {
            if r.is_valid(auth, ctx) {
                out.push(i);
            }
        }
        out
    };
    let mut valid = valid_indices(requests, auth);
    let mut previous: Vec<usize> = Vec::new();
    let mut loop_count = 0;
    let loop_max = requests.len() + 10;
    while valid != previous {
        previous = valid.clone();
        let mut preload = Vec::new();
        let mut new_mntners = Vec::new();
        for &i in &valid {
            if let Request::Change(c) = &requests[i]
                && let Some(item) = c.preload_item()
            {
                if c.request_type == Some(UpdateRequestType::Create) && item.key.0 == "mntner" {
                    new_mntners.push(item.key.1.clone());
                }
                preload.push(item);
            }
        }
        refs.preload(&preload);
        auth.pre_approve(new_mntners);
        for &i in &valid {
            match &mut requests[i] {
                Request::Change(c) => {
                    c.validate(tx, ctx, auth, refs)?;
                }
                Request::Suspension(s) => {
                    s.validate(auth, ctx);
                }
            }
        }
        valid = valid_indices(requests, auth);
        loop_count += 1;
        if loop_count > loop_max {
            let msg = messages::resolver_stuck(&ctx.meta.py_repr());
            tracing::error!(target: LOG_TARGET, "{msg}");
            return Err(Internal(msg));
        }
    }
    for r in requests.iter_mut() {
        if r.is_valid(auth, ctx) {
            match r {
                Request::Change(c) => c.save(tx, ctx)?,
                Request::Suspension(s) => s.save(tx, ctx)?,
            }
        }
    }
    Ok(())
}

/// `_resolve_pgp_key_id(pgp_fingerprint)`
fn resolve_pgp_key_id(
    tx: &mut WriteTx<'_, '_>,
    fingerprint: &str,
    meta: &RequestMeta,
) -> Result<Option<String>, Internal> {
    let clean = fingerprint.replace(' ', "");
    let tail: String = {
        let chars: Vec<char> = clean.chars().collect();
        chars[chars.len().saturating_sub(8)..].iter().collect()
    };
    let key_id = format!("PGPKEY-{tail}");
    let view = tx.read()?;
    for id in view.ids_by_rpsl_pk(&key_id)? {
        if let Some(o) = view.object_by_id(id)?
            && o.object_class == "key-cert"
        {
            let fpr = serde_json::from_str::<serde_json::Value>(o.parsed_data)
                .ok()
                .and_then(|v| {
                    v.get("fingerpr")
                        .and_then(|f| f.as_str().map(str::to_owned))
                })
                .unwrap_or_default();
            if fpr.replace(' ', "") == clean {
                return Ok(Some(key_id));
            }
        }
    }
    tracing::info!(
        target: LOG_TARGET,
        "Message was signed with key {key_id}, but key was not found in the database. Treating message as unsigned. Message metadata: {}",
        meta.py_repr()
    );
    Ok(None)
}

impl Handler {
    fn ctx<'a>(
        settings: &'a SubmitSettings,
        keyring: &'a Keyring,
        meta: &'a RequestMeta,
    ) -> Ctx<'a> {
        Ctx {
            settings,
            keyring,
            meta,
        }
    }

    /// `status()`: `SUCCESS` when every request was saved.
    pub fn status(&self) -> &'static str {
        if self.results.iter().all(|r| r.status() == Status::Saved) {
            "SUCCESS"
        } else {
            "FAILED"
        }
    }

    fn counts(&self) -> [usize; 8] {
        let saved = |r: &&Request| r.status() == Status::Saved;
        let ok: Vec<&Request> = self.results.iter().filter(saved).collect();
        let failed: Vec<&Request> = self.results.iter().filter(|r| !saved(r)).collect();
        let count =
            |list: &[&Request], t| list.iter().filter(|r| r.update_type() == Some(t)).count();
        [
            ok.len(),
            count(&ok, UpdateRequestType::Create),
            count(&ok, UpdateRequestType::Modify),
            count(&ok, UpdateRequestType::Delete),
            failed.len(),
            count(&failed, UpdateRequestType::Create),
            count(&failed, UpdateRequestType::Modify),
            count(&failed, UpdateRequestType::Delete),
        ]
    }

    /// `submitter_report_human()`
    pub fn submitter_report_human(&mut self) -> String {
        let c = self.counts();
        let mut report = self.meta.report_str();
        report.push_str(&messages::report_summary(
            self.results.len(),
            c[0],
            c[1],
            c[2],
            c[3],
            c[4],
            c[5],
            c[6],
            c[7],
        ));
        let keyring = Keyring::new();
        let ctx = Self::ctx(&self.settings, &keyring, &self.meta);
        for r in self.results.iter_mut() {
            report.push_str("---\n");
            match r {
                Request::Change(c) => report.push_str(&c.submitter_report_human()),
                Request::Suspension(s) => {
                    report.push_str(&s.submitter_report_human(&mut self.auth, &ctx))
                }
            }
            report.push('\n');
        }
        report.push_str(messages::TILDES);
        report
    }

    /// `submitter_report_json()`, serialised as Starlette's `JSONResponse`
    /// does.
    pub fn submitter_report_json(&mut self) -> String {
        let c = self.counts();
        let keyring = Keyring::new();
        let ctx = Self::ctx(&self.settings, &keyring, &self.meta);
        let mut objects = Vec::new();
        for r in self.results.iter_mut() {
            objects.push(match r {
                Request::Change(c) => c.submitter_report_json(),
                Request::Suspension(s) => s.submitter_report_json(&mut self.auth, &ctx),
            });
        }
        let mut summary = crate::json::Obj::new();
        summary.int("objects_found", self.results.len());
        summary.int("successful", c[0]);
        summary.int("successful_create", c[1]);
        summary.int("successful_modify", c[2]);
        summary.int("successful_delete", c[3]);
        summary.int("failed", c[4]);
        summary.int("failed_create", c[5]);
        summary.int("failed_modify", c[6]);
        summary.int("failed_delete", c[7]);
        let mut out = crate::json::Obj::new();
        out.raw("request_meta", &self.meta.to_json());
        out.obj("summary", &summary);
        out.obj_list("objects", &objects);
        out.finish()
    }

    /// `send_notification_target_reports()`, without the sending: every
    /// (recipient, subject, body), in v4's order (recipients in the order
    /// first seen, where v4 iterates a set).
    pub fn notification_reports(&self) -> Result<Vec<(String, String, String)>, Internal> {
        // recipient -> (auth failure reports, saved reports), each an
        // OrderedSet of report texts.
        let mut per_recipient: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
        let mut sources: Vec<String> = Vec::new();
        for r in &self.results {
            let Request::Change(c) = r else { continue };
            for target in c.notification_targets() {
                if !matches!(c.status, Status::Saved | Status::ErrorAuth) {
                    continue;
                }
                let idx = match per_recipient.iter().position(|(t, _, _)| *t == target) {
                    Some(i) => i,
                    None => {
                        per_recipient.push((target.clone(), Vec::new(), Vec::new()));
                        per_recipient.len() - 1
                    }
                };
                let report = c.notification_target_report();
                let list = if c.status == Status::ErrorAuth {
                    &mut per_recipient[idx].1
                } else {
                    &mut per_recipient[idx].2
                };
                if !list.contains(&report) {
                    list.push(report);
                }
                if let Some(o) = &c.rpsl_obj_new
                    && let Ok(s) = o.source()
                    && !sources.iter().any(|x| x == s)
                {
                    sources.push(s.to_owned());
                }
            }
        }
        let sources_str = sources.join("/");
        let subject = messages::notification_subject(&sources_str);
        let mut header =
            crate::format_sources_str(&self.settings.notification_header, &sources_str)?;
        header.push_str(messages::NOTIFICATION_AUTO);
        let mut out = Vec::new();
        for (recipient, failed, saved) in per_recipient {
            let mut body = header.clone();
            body.push_str(&self.meta.report_str());
            if !failed.is_empty() {
                body.push_str(messages::NOTIFICATION_FAILED);
                for r in &failed {
                    body.push_str(&format!("---\n{r}\n"));
                }
                body.push_str(messages::TILDES);
                body.push('\n');
            }
            if !saved.is_empty() {
                body.push_str(messages::NOTIFICATION_SAVED);
                for r in &saved {
                    body.push_str(&format!("---\n{r}\n"));
                }
                body.push_str(messages::TILDES);
                body.push('\n');
            }
            out.push((recipient, subject.clone(), body));
        }
        Ok(out)
    }

    /// `send_notification_target_reports()`
    pub fn send_notification_target_reports(&self) -> Result<(), Internal> {
        for (recipient, subject, body) in self.notification_reports()? {
            crate::send_email(&self.settings.mail, &recipient, &subject, &body)?;
        }
        Ok(())
    }

    /// `repr()` of every request's object, for logging.
    pub fn objects_repr(&self) -> String {
        self.results
            .iter()
            .map(Request::object_repr)
            .collect::<Vec<_>>()
            .join(", ")
    }
}
