//! User-facing strings, copied verbatim from IRRd v4 at the pinned baseline.
//!
//! Every message a client, operator or mail recipient can see lives here, so a
//! parity fix to wording touches exactly one place. Each item names the v4
//! file it comes from (v4.5.4).

// ---------------------------------------------------------------------------
// irrd/updates/parser.py
// ---------------------------------------------------------------------------

/// parser.py `_retrieve_existing_version` and `__init__`
pub fn not_authoritative(source: &str) -> String {
    format!("This instance is not authoritative for source {source}")
}

/// parser.py `__init__`
pub fn object_class_filtered(class: &str) -> String {
    format!("Can not make changes to {class} objects in this database")
}

/// parser.py `__init__`
pub const DELETE_NOT_FOUND: &str =
    "Can not delete object: no object found for this key in this database.";

/// parser.py `save`
pub const IDENTICAL_OBJECT: &str =
    "Submitted object was identical to current object, no change recorded.";

/// parser.py `_check_conflicting_roa`
pub fn roa_conflict(import_timer: &str) -> String {
    format!(
        "RPKI ROAs were found that conflict with this object. (This IRRd refreshes ROAs every {import_timer} seconds.)"
    )
}

/// parser.py `_check_scopefilter`
pub fn out_of_scope(comment: &str) -> String {
    format!("Contains out of scope information: {comment}")
}

/// scopefilter/validators.py `_validate_rpsl_data`
pub fn prefix_out_of_scope(prefix: &str) -> String {
    format!("prefix {prefix} is out of scope")
}

/// scopefilter/validators.py `_validate_rpsl_data`
pub fn asn_out_of_scope(asn: u32) -> String {
    format!("ASN {asn} is out of scope")
}

/// parser.py `SuspensionRequest.__init__`
pub fn unknown_suspension_type(state: &str) -> String {
    format!("Unknown suspension type: {state}")
}

/// parser.py `SuspensionRequest.__init__`
pub fn suspension_not_enabled(source: &str) -> String {
    format!("This instance is not authoritative for source {source} or suspension is not enabled")
}

/// parser.py `SuspensionRequest.__init__`
pub const SUSPENSION_MNTNER_ONLY: &str =
    "Suspensions/reactivations can only be done on mntner objects";

/// parser.py `SuspensionRequest.validate`
pub const SUSPENSION_OVERRIDE_INVALID: &str =
    "Invalid authentication: override password invalid or missing";

/// parser.py `SuspensionRequest.save`
pub fn suspended(class: &str, pk: &str, source: &str) -> String {
    format!("Suspended {class}/{pk}/{source}")
}

/// parser.py `SuspensionRequest.save`
pub fn restored(obj: &str) -> String {
    format!("Restored {obj}")
}

/// parser.py `object_pk_str`
pub const UNREADABLE_KEY: &str = "(unreadable object key)";

/// parser.py `object_class_str`
pub const UNREADABLE_CLASS: &str = "(unreadable object class)";

// ---------------------------------------------------------------------------
// irrd/updates/validators.py
// ---------------------------------------------------------------------------

/// validators.py `check_references_to_others`
pub fn reference_not_found(pk: &str, field: &str, source: &str, referred: &str) -> String {
    format!(
        "Object {pk} referenced in field {field} not found in database {source} - must reference {referred}."
    )
}

/// validators.py `check_references_from_others_for_deletion`, with override
pub fn delete_reference_override(pk: &str, class: &str, referring: &str) -> String {
    format!(
        "NOTE: object {pk} still referenced by {class} {referring}. Delete permitted due to override. This creates a broken reference."
    )
}

/// validators.py `check_references_from_others_for_deletion`
pub fn delete_still_referenced(pk: &str, class: &str, referring: &str) -> String {
    format!("Object {pk} to be deleted, but still referenced by {class} {referring}")
}

/// validators.py `check_protected_name`, with override
pub fn create_references_override(pk: &str, class: &str, referring: &str) -> String {
    format!(
        "NOTE: existing references to {pk} exist from {class} {referring}, permitted due to override"
    )
}

/// validators.py `check_protected_name`
pub fn create_references_exist(pk: &str, class: &str, referring: &str) -> String {
    format!("Object {pk} to be created, but existing references exist from {class} {referring}")
}

/// validators.py `check_protected_name`, with override
pub fn protected_name_override(pk: &str) -> String {
    format!("NOTE: object {pk} has a protected name, creation permitted due to override.")
}

/// validators.py `check_protected_name`
pub fn protected_name(pk: &str) -> String {
    format!(
        "Object {pk} has a protected name that can not be reused. Create the object under a different name."
    )
}

/// validators.py `process_auth`
pub fn too_many_passwords(max: usize) -> String {
    format!("Submissions may include at most {max} distinct passwords.")
}

/// validators.py `process_auth`
pub const NEW_MNTNER_NEEDS_ADMIN: &str = "New mntner objects must be added by an administrator.";

/// validators.py `process_auth`
pub const DUMMY_HASHES_REPLACED: &str = "As you submitted dummy hash values, all password hashes on this object were replaced with a new BCRYPT-PW hash of the password you provided for authentication.";

/// validators.py `process_auth`
pub const DUMMY_HASHES_NEED_ONE_PASSWORD: &str = "Object submitted with dummy hash values, but multiple or no passwords submitted. Either submit only full hashes, or a single password.";

/// validators.py `process_auth`
pub const MNTNER_AUTH_FAILED: &str =
    "Authorisation failed for the auth methods on this mntner object.";

/// validators.py `_generate_failure_message`
pub fn auth_failed(class: &str, pk: &str, mntners: &str, parent: Option<(&str, &str)>) -> String {
    let mut msg = format!(
        "Authorisation for {class} {pk} failed: must be authenticated by one of: {mntners}"
    );
    if let Some((pclass, ppk)) = parent {
        msg.push_str(&format!(" - from parent {pclass} {ppk}"));
    }
    msg
}

/// validators.py `_find_related_object_set`
pub fn set_requires_autnum(segment: &str) -> String {
    format!("Creating this object requires an aut-num for {segment} to exist.")
}

/// validators.py `RulesValidator.validate`
pub fn route_not_permitted(prefix: &str) -> String {
    format!("Route(6) objects for {prefix} are not permitted.")
}

/// validators.py `RulesValidator.validate`
pub fn suspended_mntner_exists(pk: &str, source: &str) -> String {
    format!("A suspended mntner with primary key {pk} already exists for {source}")
}

/// validators.py `RulesValidator.validate`
pub fn mntner_migrated_needs_internal(method: &str) -> String {
    format!("This maintainer is migrated and must include the {method} method.")
}

/// validators.py `RulesValidator.validate`
pub fn mntner_not_migrated(method: &str) -> String {
    format!("This maintainer is not migrated, and therefore can not use the {method} method.")
}

// ---------------------------------------------------------------------------
// irrd/updates/suspension.py
// ---------------------------------------------------------------------------

/// suspension.py
pub fn suspension_not_authoritative(source: &str) -> String {
    format!("Not authoritative for source {source}")
}

/// suspension.py `suspend_for_mntner`
pub fn suspend_mntner_missing(pk: &str, source: &str) -> String {
    format!("mntner {pk} does not exist in {source} (or may already be suspended)")
}

/// suspension.py `reactivate_for_mntner`
pub fn reactivate_active_exists(source: &str, pk: &str) -> String {
    format!(
        "source {source} has a currently active mntner {pk} - can not restore the suspended one"
    )
}

/// suspension.py `reactivate_for_mntner`
pub fn reactivate_not_suspended(pk: &str, source: &str) -> String {
    format!("mntner {pk} not found in suspended store for source {source}")
}

/// suspension.py `reactivate_for_mntner`
pub fn reactivate_skipped(obj: &str) -> String {
    format!("Skipping restore of object {obj} - an object already exists with the same key")
}

// ---------------------------------------------------------------------------
// irrd/updates/handler.py
// ---------------------------------------------------------------------------

/// handler.py `submitter_report_human`: the summary, after `textwrap.dedent`.
#[allow(clippy::too_many_arguments)]
pub fn report_summary(
    found: usize,
    ok: usize,
    ok_create: usize,
    ok_modify: usize,
    ok_delete: usize,
    failed: usize,
    failed_create: usize,
    failed_modify: usize,
    failed_delete: usize,
) -> String {
    format!(
        "\nSUMMARY OF UPDATE:\n\nNumber of objects found:                  {found:>3}\nNumber of objects processed successfully: {ok:>3}\n    Create:      {ok_create:>3}\n    Modify:      {ok_modify:>3}\n    Delete:      {ok_delete:>3}\nNumber of objects processed with errors:  {failed:>3}\n    Create:      {failed_create:>3}\n    Modify:      {failed_modify:>3}\n    Delete:      {failed_delete:>3}\n\nDETAILED EXPLANATION:\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
    )
}

/// handler.py: the line that closes each block of a report.
pub const TILDES: &str = "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";

/// handler.py `send_notification_target_reports`
pub fn notification_subject(sources: &str) -> String {
    format!("Notification of {sources} database changes")
}

/// handler.py `send_notification_target_reports`
pub const NOTIFICATION_AUTO: &str =
    "\nThis message is auto-generated.\nThe request was made with the following details:\n";

/// handler.py `send_notification_target_reports`: `header_saved`.
pub const NOTIFICATION_SAVED: &str = "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\nSome objects in which you are referenced have been created,\ndeleted or changed.\n\n";

/// handler.py `send_notification_target_reports`: `header_failed`, with
/// v4's trailing space after "the".
pub const NOTIFICATION_FAILED: &str = "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\nSome objects in which you are referenced were requested\nto be created, deleted or changed, but *failed* the \nproper authorisation for any of the referenced maintainers.\n\n";

/// conf/default_config.yaml `email.notification_header`
pub const DEFAULT_NOTIFICATION_HEADER: &str = "This is to notify you of changes in the {sources_str} database\nor object authorisation failures.\n\nYou may receive this message because you are listed in\nthe notify attribute on the changed object(s), because\nyou are listed in the mnt-nfy or upd-to attribute on a maintainer\nof the object(s), or the upd-to attribute on the maintainer of a\nparent of newly created object(s).\n";

/// handler.py `_handle_change_requests`
pub fn resolver_stuck(meta: &str) -> String {
    format!(
        "Update validity resolver ran an excessive amount of loops, may be stuck, aborting processing. Message metadata: {meta}"
    )
}

// ---------------------------------------------------------------------------
// irrd/updates/email.py
// ---------------------------------------------------------------------------

/// email.py `handle_email_submission`
pub fn email_no_text_plain(message_id: &str) -> String {
    format!(
        "\nUnfortunately, your message with ID {message_id}\ncould not be processed, as no text/plain part could be found.\n\nPlease try to resend your message as plain text email.\n"
    )
}

/// email.py `handle_email_submission`
pub fn email_internal_error(message_id: &str) -> String {
    format!(
        "\nUnfortunately, your message with ID {message_id}\ncould not be processed, due to an internal error.\n"
    )
}

/// scripts/submit_email.py `run`
pub const SUBMIT_EMAIL_INTERNAL_ERROR: &str =
    "An internal error occurred while processing this email.";
