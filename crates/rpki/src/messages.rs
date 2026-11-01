//! User-facing strings, copied verbatim from IRRd v4 at the pinned baseline.
//!
//! Every message a client, operator or mail recipient can see lives here, so a
//! parity fix to wording touches exactly one place.

// ---- irrd/rpki/importer.py ----

/// `f"Unable to parse ROA input: invalid JSON: {error}"`
pub fn invalid_json(error: &str) -> String {
    format!("Unable to parse ROA input: invalid JSON: {error}")
}

/// `'Unable to parse ROA input: root key "roas" not found'`
pub const ROOT_KEY_NOT_FOUND: &str = "Unable to parse ROA input: root key \"roas\" not found";

/// `f"Unable to parse ROA record: missing key {ke} -- full record: {roa_dict}"`
pub fn missing_key(key_repr: &str, record: &str) -> String {
    format!("Unable to parse ROA record: missing key {key_repr} -- full record: {record}")
}

/// `f"Invalid value in ROA or SLURM: {ve}"`
pub fn invalid_value_roa_or_slurm(ve: &str) -> String {
    format!("Invalid value in ROA or SLURM: {ve}")
}

/// `f"SLURM data has invalid version: {version}"`
pub fn slurm_invalid_version(version: &str) -> String {
    format!("SLURM data has invalid version: {version}")
}

/// `f"Invalid value in ROA: {ve}"`
pub fn invalid_value_in_roa(ve: &str) -> String {
    format!("Invalid value in ROA: {ve}")
}

/// `f"Invalid ROA: prefix size {prefixlen} is smaller than max length {max_length} in ROA for {prefix} / AS{asn}"`
pub fn max_length_too_small(prefixlen: u32, max_length: &str, prefix: &str, asn: u32) -> String {
    format!(
        "Invalid ROA: prefix size {prefixlen} is smaller than max length {max_length} in ROA for {prefix} / AS{asn}"
    )
}

/// `parse_as_number`'s range error for an integer value.
pub fn asn_out_of_range(value: &str) -> String {
    format!("Invalid AS number {value}: valid range is 0-4294967295")
}

/// CPython's `int()` error for a string.
pub fn int_invalid_literal(repr: &str) -> String {
    format!("invalid literal for int() with base 10: {repr}")
}

/// CPython's `int()` error for a value of the wrong type.
pub fn int_type_error(type_name: &str) -> String {
    format!(
        "int() argument must be a string, a bytes-like object or a real number, not '{type_name}'"
    )
}

/// irrd-ng: an integer v4 would accept but no column can hold.
pub fn int_too_large() -> String {
    "integer out of range".to_owned()
}

/// irrd-ng: a ROA field of a JSON type v4 does not handle either (it
/// fails with a `TypeError` or `AttributeError` of its own).
pub fn unsupported_value(field: &str, type_name: &str) -> String {
    format!("unsupported {type_name} value for {field}")
}

/// `str.format()` on `pseudo_irr_remarks`: a lone `}`.
pub const FORMAT_SINGLE_CLOSE_BRACE: &str = "Single '}' encountered in format string";

/// `str.format()` on `pseudo_irr_remarks`: an unclosed `{`.
pub const FORMAT_UNCLOSED_BRACE: &str = "expected '}' before end of string";

/// The integrity error v4 hits when two ROAs give the same pseudo-IRR
/// object. psycopg2's text, as SQLAlchemy prefixes it; v4 also appends the
/// statement and its parameters, which are left out.
pub fn pseudo_irr_unique_violation(rpsl_pk: &str, source: &str, object_class: &str) -> String {
    format!(
        "(psycopg2.errors.UniqueViolation) duplicate key value violates unique constraint \"rpsl_objects_rpsl_pk_source_class_unique\"\nDETAIL:  Key (rpsl_pk, source, object_class)=({rpsl_pk}, {source}, {object_class}) already exists.\n"
    )
}

/// `DatabaseHandler._flush_rpsl_object_writing_buffer()` logs the failing
/// statement before re-raising. v4 prints the whole multi-row statement
/// with a placeholder per value; the values part is left out here.
pub const INSERT_STATEMENT_FAILED: &str = "Exception occurred while executing statement: INSERT INTO rpsl_objects (rpsl_pk, source, object_class, parsed_data, object_text, ip_version, ip_first, ip_last, ip_size, prefix_length, prefix, asn_first, asn_last, rpki_status, scopefilter_status, route_preference_status, updated) VALUES ..., rolling back";

// ---- irrd/mirroring/mirror_runners_import.py ----

/// `f"Running full ROA import from: {roa_source}, SLURM {slurm_source}"`
pub fn roa_import_running(roa_source: &str, slurm_source: &str) -> String {
    format!("Running full ROA import from: {roa_source}, SLURM {slurm_source}")
}

/// `f"ROA import from {roa_source}, SLURM {slurm_source}, imported {n} ROAs, running validator"`
pub fn roa_import_imported(roa_source: &str, slurm_source: &str, n: usize) -> String {
    format!(
        "ROA import from {roa_source}, SLURM {slurm_source}, imported {n} ROAs, running validator"
    )
}

/// The summary after the RPKI status update.
pub fn rpki_status_updated(
    valid: usize,
    invalid: usize,
    not_found: usize,
    notified: usize,
) -> String {
    format!(
        "RPKI status updated for all routes, {valid} newly valid, {invalid} newly invalid, {not_found} newly not_found routes, {notified} emails sent to contacts of newly invalid authoritative objects"
    )
}

/// `f"An error occurred while attempting a ROA import: {ose}"`
pub fn roa_import_os_error(e: &str) -> String {
    format!("An error occurred while attempting a ROA import: {e}")
}

/// `f"An exception occurred while attempting a ROA import: {exc}"`
pub fn roa_import_exception(e: &str) -> String {
    format!("An exception occurred while attempting a ROA import: {e}")
}

/// The summary after a scope filter update.
pub fn scopefilter_updated(in_scope: usize, out_as: usize, out_prefix: usize) -> String {
    format!(
        "Scopefilter status updated for all routes, {in_scope} newly in scope, {out_as} newly out of scope AS, {out_prefix} newly out of scope prefix"
    )
}

/// `f"An exception occurred while attempting a scopefilter status update: {exc}"`
pub fn scopefilter_exception(e: &str) -> String {
    format!("An exception occurred while attempting a scopefilter status update: {e}")
}

/// `"route preference update commit complete"`
pub const ROUTEPREF_COMMIT_COMPLETE: &str = "route preference update commit complete";

/// `f"An exception occurred while attempting a route preference status update: {exc}"`
pub fn routepref_exception(e: &str) -> String {
    format!("An exception occurred while attempting a route preference status update: {e}")
}

// ---- irrd/routepref/routepref.py ----

/// `common_log` of `update_route_preference_status`.
pub fn routepref_common(visible: usize, suppressed: usize, excluded_visible: usize) -> String {
    format!(
        "{visible} regular objects made visible, {suppressed} regular objects suppressed, {excluded_visible} objects from excluded sources made visible"
    )
}

/// `f"route preference updated for all routes: {common_log}"`
pub fn routepref_all(common: &str) -> String {
    format!("route preference updated for all routes: {common}")
}

/// `f"route preference updated for a subset of {n} added/removed/changed routes: {common_log}"`
pub fn routepref_subset(n: usize, common: &str) -> String {
    format!("route preference updated for a subset of {n} added/removed/changed routes: {common}")
}

// ---- irrd/rpki/notifications.py ----

/// The text between the header and the objects.
pub const NOTIFY_AFFECTED: &str = "\nThe following objects are affected:\n";

/// The rule around the objects.
pub const NOTIFY_RULE: &str = "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~";

/// `f"Unable to send RPKI invalid notification to {email}: {e}"`
pub fn notify_send_failed(email: &str, e: &str) -> String {
    format!("Unable to send RPKI invalid notification to {email}: {e}")
}
