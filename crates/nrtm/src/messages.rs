//! User-facing strings, copied verbatim from IRRd v4 at the pinned baseline.
//!
//! Every message a client, operator or mail recipient can see lives here, so a
//! parity fix to wording touches exactly one place.

// irrd/mirroring/parsers.py

/// `MirrorFileImportParserBase.parse_object`: parser errors.
pub fn parsing_errors(errors_repr: &str, rpsl_text: &str) -> String {
    format!("Parsing errors: {errors_repr}, original object text follows:\n{rpsl_text}")
}

/// `parse_object`: the critical log line for parser errors.
pub fn parsing_errors_log(source: &str, errors_repr: &str, rpsl_text: &str) -> String {
    format!(
        "Parsing errors occurred while importing from file for {source}. This object is ignored, \
         causing potential data inconsistencies. A new operation for this update, without errors, \
         will still be processed and cause the inconsistency to be resolved. Parser error messages: \
         {errors_repr}; original object text follows:\n{rpsl_text}"
    )
}

/// `parse_object`: wrong source.
pub fn invalid_source(found: &str, pk: &str, expected: &str) -> String {
    format!("Invalid source {found} for object {pk}, expected {expected}")
}

/// `parse_object`: the critical log line for a wrong source.
pub fn invalid_source_log(msg: &str) -> String {
    format!("{msg}. This object is ignored, causing potential data inconsistencies.")
}

/// `parse_object`: an unknown object class with `direct_error_return`.
pub fn unknown_object_class(class: &str) -> String {
    format!("Unknown object class: {class}")
}

/// `log_report_with_prefix`.
pub fn file_import_report(
    source: &str,
    parsed: i64,
    successful: i64,
    errors: i64,
    ignored_class: i64,
) -> String {
    format!(
        "File import for {source}: {parsed} objects read, {successful} objects inserted, \
         ignored {errors} due to errors, ignored {ignored_class} due to object_class_filter"
    )
}

/// `log_unknown_object_classes`.
pub fn unknown_classes_report(count: i64, source: &str, classes: &str) -> String {
    format!(
        "Ignored {count} objects found in import for {source} due to unknown object classes: {classes}"
    )
}

/// `MirrorUpdateFileImportParser.log_report`.
#[allow(clippy::too_many_arguments)]
pub fn file_update_report(
    source: &str,
    parsed: i64,
    successful: i64,
    new: i64,
    deleted: i64,
    retained: i64,
    modified: i64,
    errors: i64,
    ignored_class: i64,
    filename: &str,
) -> String {
    format!(
        "File update for {source}: {parsed} objects read, {successful} objects processed, \
         {new} objects newly inserted, {deleted} objects newly deleted, {retained} objects retained, \
         of which {modified} modified, ignored {errors} due to errors, ignored {ignored_class} due \
         to object_class_filter, source {filename}"
    )
}

/// `MirrorFileImportParser.__init__` (debug).
pub fn starting_file_import(source: &str, filename: &str) -> String {
    format!("Starting file import of {source} from {filename}")
}

/// `MirrorUpdateFileImportParser.__init__` (debug).
pub fn starting_update_import(source: &str, filename: &str) -> String {
    format!("Starting update import for {source} from {filename}")
}
