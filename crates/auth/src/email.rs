//! `irrd/updates/email.py` `handle_email_submission`: process an e-mail,
//! reply to its sender and notify the contacts of the changed objects.

use std::sync::Arc;

use store::Store;

use crate::email_parser::{EmailParser, reply_addresses};
use crate::handler::{Handler, Submission, process};
use crate::meta::RequestMeta;
use crate::settings::SubmitSettings;
use crate::{Origin, messages};

/// v4's logger.
pub const LOG_TARGET: &str = "irrd.updates.email";

/// What happened, for callers and tests: the reply that was (or would
/// have been) sent and the notifications.
#[derive(Debug, Default)]
pub struct EmailOutcome {
    /// The handler, when the message was processed.
    pub handler: Option<Handler>,
    /// (recipient, subject, body) of the reply, when one was sent.
    pub reply: Option<(String, String, String)>,
}

/// `handle_email_submission(email_txt)`; mail goes out through `send`.
pub fn handle_email_submission(
    store: &Store,
    settings: Arc<SubmitSettings>,
    email_txt: &str,
    send: &mut dyn FnMut(&str, &str, &str) -> Result<(), crate::Internal>,
) -> EmailOutcome {
    let mut outcome = EmailOutcome::default();
    let keyring = match store.read().and_then(|r| r.view().pgp_keyring()) {
        Ok(k) => rpsl::Keyring::from_entries(k),
        Err(e) => {
            log_parse_exception(email_txt, &e.to_string());
            return outcome;
        }
    };
    let msg = match EmailParser::parse(email_txt, &keyring) {
        Ok(m) => m,
        Err(e) => {
            log_parse_exception(email_txt, &e);
            return outcome;
        }
    };
    let mut meta = RequestMeta::default();
    meta.set_opt("Message-ID", msg.message_id.as_deref());
    meta.set_opt("From", msg.message_from.as_deref());
    meta.set_opt("Date", msg.message_date.as_deref());
    meta.set_opt("Subject", msg.message_subject.as_deref());

    let Some(from) = msg.message_from.clone().filter(|f| !f.is_empty()) else {
        tracing::error!(
            target: LOG_TARGET,
            critical = true,
            "No from address was found while attempting to parse the following update e-mail - update not processed: {email_txt}\n"
        );
        return outcome;
    };
    let message_id = msg.message_id.clone().unwrap_or_else(|| "None".to_owned());
    let subject_str = msg
        .message_subject
        .clone()
        .unwrap_or_else(|| "None".to_owned());

    let (subject, reply_content) = match msg.body.clone().filter(|b| !b.is_empty()) {
        None => {
            tracing::warn!(target: LOG_TARGET, "Unable to extract message body from e-mail {message_id} from {from}");
            (
                format!("FAILED: {subject_str}"),
                messages::email_no_text_plain(&message_id),
            )
        }
        Some(body) => {
            match process(
                store,
                settings.clone(),
                Submission::TextBlob {
                    text: body,
                    origin: Origin::Email,
                    pgp_fingerprint: msg.pgp_fingerprint.clone(),
                },
                meta,
            ) {
                Ok(mut handler) => {
                    tracing::info!(target: LOG_TARGET, "Processed e-mail {message_id} from {from}: {}", handler.status());
                    // v4 builds the report for its debug log whether or not
                    // debug logging is on; for suspension requests that has
                    // side effects on the report sent.
                    let debug_report = handler.submitter_report_human();
                    tracing::debug!(target: LOG_TARGET, "Report for e-mail {message_id} from {from}: {debug_report}");
                    let subject = format!("{}: {subject_str}", handler.status());
                    let report = handler.submitter_report_human();
                    outcome.handler = Some(handler);
                    (subject, report)
                }
                Err(e) => {
                    tracing::error!(
                        target: LOG_TARGET,
                        critical = true,
                        "An exception occurred while attempting to process the following update: {email_txt}\n--- traceback for {e} follows:"
                    );
                    (
                        format!("ERROR: {subject_str}"),
                        messages::email_internal_error(&message_id),
                    )
                }
            }
        }
    };

    let addresses = reply_addresses(&from);
    let mut result = Ok(());
    if addresses.len() == 1 {
        outcome.reply = Some((addresses[0].clone(), subject.clone(), reply_content.clone()));
        result = send(&addresses[0], &subject, &reply_content);
    } else {
        tracing::warn!(
            target: LOG_TARGET,
            "Unable to extract a single reply address from From header {} in e-mail {message_id} - submission was processed, but no reply sent",
            crate::json::py_str_repr(&from)
        );
    }
    if result.is_ok()
        && let Some(h) = &outcome.handler
    {
        result = h.notification_reports().and_then(|reports| {
            for (r, s, b) in reports {
                send(&r, &s, &b)?;
            }
            Ok(())
        });
    }
    if let Err(e) = result {
        tracing::error!(
            target: LOG_TARGET,
            critical = true,
            "An exception occurred while attempting to send a reply to an update: {subject}\n{reply_content}\n --- traceback for {e} follows:"
        );
    }
    outcome
}

fn log_parse_exception(email_txt: &str, e: &str) {
    tracing::error!(
        target: LOG_TARGET,
        critical = true,
        "An exception occurred while attempting to parse the following update e-mail: {email_txt}\n--- traceback for {e} follows:"
    );
}
