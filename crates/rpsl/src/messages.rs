//! User-facing strings, copied verbatim from IRRd v4 at the pinned baseline.
//!
//! Every message a client, operator or mail recipient can see lives here, so a
//! parity fix to wording touches exactly one place. Each function names the
//! v4 file and the line its text comes from (v4.5.4).

use std::fmt::Display;

// ---------------------------------------------------------------------------
// irrd/rpsl/parser.py
// ---------------------------------------------------------------------------

/// parser.py:279
pub(crate) fn empty_line_in_object(line_no: usize, line: &str) -> String {
    format!("Line {line_no}: encountered empty line in the middle of object: [{line}]")
}

/// parser.py:292
pub(crate) fn neither_continuation_nor_attribute(line_no: usize, line: &str) -> String {
    format!("Line {line_no}: line is neither continuation nor valid attribute [{line}]")
}

/// parser.py:302
pub(crate) fn malformed_attribute_name(line_no: usize, attr: &str) -> String {
    format!("Line {line_no}: encountered malformed attribute name: [{attr}]")
}

/// parser.py:341
pub(crate) fn unrecognised_attribute(attr: &str, class: &str) -> String {
    format!("Unrecognised attribute {attr} on object {class}")
}

/// parser.py:345
pub(crate) fn attribute_multiple(attr: &str, class: &str) -> String {
    format!(
        "Attribute \"{attr}\" on object {class} occurs multiple times, but is only allowed once"
    )
}

/// parser.py:351
pub(crate) fn mandatory_missing(attr: &str, class: &str) -> String {
    format!("Mandatory attribute \"{attr}\" on object {class} is missing")
}

/// parser.py:360
pub(crate) fn primary_key_missing(attr: &str, class: &str) -> String {
    format!("Primary key attribute \"{attr}\" on object {class} is missing")
}

/// parser.py:432 (raised as `ValueError`; the missing space after the comma
/// is v4's).
pub(crate) fn metadata_already_set(
    value: &str,
    attr_value: &dyn Display,
    attr: &str,
    existing: &dyn Display,
) -> String {
    format!("Parsing of {value} reads {attr_value} for {attr},but value {existing} is already set.")
}

/// parser.py:136 (raised as `ValueError`).
pub const NO_KNOWN_SOURCE: &str = "RPSL object has no known source";

/// parser.py:233-237, template metadata.
pub(crate) const TEMPLATE_PRIMARY_LOOKUP_KEY: &str = "primary/look-up key";
pub(crate) const TEMPLATE_PRIMARY_KEY: &str = "primary key";
pub(crate) const TEMPLATE_LOOKUP_KEY: &str = "look-up key";

// ---------------------------------------------------------------------------
// irrd/rpsl/rpsl_objects.py
// ---------------------------------------------------------------------------

/// rpsl_objects.py:49
pub(crate) fn unknown_object_class(class: &str) -> String {
    format!("unknown object class: {class}")
}

/// rpsl_objects.py:67
pub(crate) fn set_name_not_hierarchical(class: &str, segment: &str, error: &str) -> String {
    format!(
        "{class} names must be hierarchical and the first component must be an AS number, e.g. \"AS65537:{segment}\": {error}"
    )
}

/// rpsl_objects.py:386
pub(crate) const PGP_KEY_UNREADABLE: &str =
    "Unable to read public PGP key: key corrupt or multiple keys provided";

/// rpsl_objects.py:399
pub(crate) fn key_cert_name_mismatch(actual: &str, fingerprint: &str, expected: &str) -> String {
    format!(
        "Invalid object name {actual}: does not match key fingerprint {fingerprint}, expected object name {expected}"
    )
}

/// rpsl_objects.py:466
pub(crate) const MNTNER_DUMMY_MIX: &str =
    "Either all password auth hashes in a submitted mntner must be dummy objects, or none.";

// ---------------------------------------------------------------------------
// irrd/rpsl/fields.py
// ---------------------------------------------------------------------------

/// fields.py:153, fields.py:188
pub(crate) fn invalid_prefix(value: &str) -> String {
    format!("Invalid address prefix: {value}")
}

/// fields.py:160, fields.py:195
pub(crate) fn invalid_prefix_detail(value: &str, error: &str) -> String {
    format!("Invalid address prefix: {value}: {error}")
}

/// fields.py:167, fields.py:202
pub(crate) fn prefix_reformatted(value: &str, parsed: &str) -> String {
    format!("Address prefix {value} was reformatted as {parsed}")
}

/// fields.py:238
pub(crate) fn invalid_range_detail(value: &str, error: &str) -> String {
    format!("Invalid address range: {value}: {error}")
}

/// fields.py:242
pub(crate) fn invalid_range_version(value: &str) -> String {
    format!("Invalid address range: {value}: IP version mismatch")
}

/// fields.py:245
pub(crate) fn invalid_range_order(value: &str) -> String {
    format!("Invalid address range: {value}: first IP is higher than second IP")
}

/// fields.py:253
pub(crate) fn range_reformatted(value: &str, parsed: &str) -> String {
    format!("Address range {value} was reformatted as {parsed}")
}

/// fields.py:283
pub(crate) fn missing_range_operator(value: &str) -> String {
    format!("Missing range operator in value: {value}")
}

/// fields.py:298, 306, 357
pub(crate) fn route_set_member_reformatted(value: &str, parsed: &str) -> String {
    format!("Route set member {value} was reformatted as {parsed}")
}

/// fields.py:316
pub(crate) fn not_set_name_nor_prefix(address: &str, error: &str) -> String {
    format!("Value is neither a valid set name nor a valid prefix: {address}: {error}")
}

/// fields.py:322
pub(crate) fn invalid_range_operator(op: &str, value: &str) -> String {
    format!("Invalid range operator {op} in value: {value}")
}

/// fields.py:328
pub(crate) fn range_operator_length(single: &str, prefixlen: u32, value: &str) -> String {
    format!(
        "Invalid range operator: operator length ({single}) must be equal to or longer than prefix length ({prefixlen}) {value}"
    )
}

/// fields.py:337
pub(crate) fn range_operator_start(start: &str, prefixlen: u32, value: &str) -> String {
    format!(
        "Invalid range operator: operator start ({start}) must be equal to or longer than prefix length ({prefixlen}) {value}"
    )
}

/// fields.py:343
pub(crate) fn range_operator_end(end: &str, start: &str, value: &str) -> String {
    format!(
        "Invalid range operator: operator end ({end}) must be equal to or longer than operator start ({start}) {value}"
    )
}

/// fields.py:379
pub(crate) fn as_number_reformatted(value: &str, parsed: &str) -> String {
    format!("AS number {value} was reformatted as {parsed}")
}

/// fields.py:392
pub(crate) fn as_range_no_hyphen(value: &str) -> String {
    format!("Invalid AS range: {value}: does not contain a hyphen")
}

/// fields.py:405 ("then" is v4's).
pub(crate) fn as_range_order(value: &str) -> String {
    format!("Invalid AS range: {value}: first AS is higher then second AS")
}

/// fields.py:410
pub(crate) fn as_range_reformatted(value: &str, parsed: &str) -> String {
    format!("AS range {value} was reformatted as {parsed}")
}

/// fields.py:447, fields.py:466
pub(crate) fn invalid_email(value: &str) -> String {
    format!("Invalid e-mail address: {value}")
}

/// fields.py:472
pub(crate) fn invalid_changed_date(date: &str, error: &str) -> String {
    format!("Invalid changed date: {date}: {error}")
}

/// fields.py:486
pub(crate) fn invalid_dns_name(value: &str) -> String {
    format!("Invalid DNS name: {value}")
}

/// fields.py:503
pub(crate) fn invalid_url(schemes: &str, value: &str) -> String {
    format!("Invalid {schemes} URL: {value}")
}

/// fields.py:543
pub(crate) fn name_reserved_word(value: &str) -> String {
    format!("Invalid name: {value}: this is a reserved word")
}

/// fields.py:548
pub(crate) fn name_reserved_prefix(value: &str, prefix: &str) -> String {
    format!("Invalid name: {value}: {prefix} is a reserved prefix")
}

/// fields.py:553
pub(crate) fn name_invalid(value: &str) -> String {
    format!(
        "Invalid name: {value}: contains invalid characters, does not start with a letter, or does not end in a letter/digit"
    )
}

/// fields.py:649
pub(crate) fn invalid_auth_detail(value: &str, error: &str) -> String {
    format!("Invalid auth attribute: {value}: {error}")
}

/// fields.py:655
pub(crate) fn invalid_auth(value: &str, hashers: &str, internal: &str) -> String {
    format!(
        "Invalid auth attribute: {value}: supported options are {hashers}, PGPKEY-xxxxxxxx and {internal} for migrated objects"
    )
}

/// fields.py:670
pub(crate) const SET_NAME_TOO_MANY_COMPONENTS: &str =
    "Set names can have a maximum of five components.";

/// fields.py:675
pub(crate) fn set_name_no_set_component(value: &str, prefixes: &str) -> String {
    format!(
        "Invalid set name {value}: at least one component must be an actual set name (i.e. start with {prefixes})"
    )
}

/// fields.py:682
pub(crate) fn set_name_reserved_word(value: &str, component: &str) -> String {
    format!("Invalid set name {value}: component {component} is a reserved word")
}

/// fields.py:692
pub(crate) fn set_component_invalid(value: &str, component: &str) -> String {
    format!(
        "Invalid set {value}: component {component} is not a valid AS number nor a valid set name"
    )
}

/// fields.py:697
pub(crate) fn set_component_wrong_prefix(value: &str, component: &str, prefixes: &str) -> String {
    format!(
        "Invalid set {value}: component {component} is not a valid AS number, nor does it start with {prefixes}"
    )
}

/// fields.py:709
pub(crate) fn set_name_reformatted(value: &str, parsed: &str) -> String {
    format!("Set name {value} was reformatted as {parsed}")
}

// ---------------------------------------------------------------------------
// irrd/rpsl/auth.py
// ---------------------------------------------------------------------------

/// auth.py:32
pub(crate) const INVALID_BCRYPT_HASH: &str = "invalid bcrypt hash";

/// auth.py:34
pub(crate) fn bcrypt_cost_too_high(max: u32) -> String {
    format!("bcrypt cost factor must be {max} or lower")
}

// ---------------------------------------------------------------------------
// irrd/utils/validators.py
// ---------------------------------------------------------------------------

/// validators.py:9
pub(crate) fn asn_must_start_with_as(value: &str) -> String {
    format!("Invalid AS number {value}: must start with \"AS\"")
}

/// validators.py:17
pub(crate) fn asn_asdot_format(value: &str) -> String {
    format!("Invalid AS number {value}: number is not valid asdot format")
}

/// validators.py:22
pub(crate) fn asn_asdot_high_invalid(value: &str) -> String {
    format!("Invalid AS number {value}: high order value missing or invalid")
}

/// validators.py:26
pub(crate) fn asn_asdot_low_invalid(value: &str) -> String {
    format!("Invalid AS number {value}: low order value missing or invalid")
}

/// validators.py:29
pub(crate) fn asn_asdot_high_range(value: &str) -> String {
    format!("Invalid AS number {value}: high order value out of range")
}

/// validators.py:32
pub(crate) fn asn_asdot_low_range(value: &str) -> String {
    format!("Invalid AS number {value}: low order value out of range")
}

/// validators.py:40
pub(crate) fn asn_not_numeric(value: &str) -> String {
    format!("Invalid AS number {value}: number part is not numeric")
}

/// validators.py:46
pub(crate) fn asn_out_of_range(value: &str) -> String {
    format!("Invalid AS number {value}: valid range is 0-4294967295")
}

// ---------------------------------------------------------------------------
// CPython datetime.strptime, as surfaced by RPSLChangedField
// ---------------------------------------------------------------------------

pub(crate) fn strptime_no_match(data: &str, format: &str) -> String {
    format!("time data {data} does not match format {format}")
}

pub(crate) fn strptime_unconverted(rest: &str) -> String {
    format!("unconverted data remains: {rest}")
}

pub(crate) const DATE_DAY_OUT_OF_RANGE: &str = "day is out of range for month";

pub(crate) fn date_year_out_of_range(year: u32) -> String {
    format!("year {year} is out of range")
}

// ---------------------------------------------------------------------------
// python-gnupg ImportResult texts (gnupg.py 0.5.6), surfaced in key-cert
// errors after PGP_KEY_UNREADABLE.
// ---------------------------------------------------------------------------

pub(crate) const GPG_NO_VALID_DATA: &str = "No valid data found";
pub(crate) const GPG_OTHER_FAILURE: &str = "Other failure";
pub(crate) const GPG_KEY_EXPIRED: &str = "Key expired";
