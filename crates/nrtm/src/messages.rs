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

/// `log_report_with_prefix(prefix)`.
pub fn import_report(
    prefix: &str,
    parsed: i64,
    successful: i64,
    errors: i64,
    ignored_class: i64,
) -> String {
    format!(
        "{prefix}: {parsed} objects read, {successful} objects inserted, ignored {errors} due to \
         errors, ignored {ignored_class} due to object_class_filter"
    )
}

// irrd/mirroring/mirror_runners_import.py

/// `RPSLMirrorImportUpdateRunner.run`: an `NRTM4ClientError`.
pub fn nrtm4_validation_errors(source: &str, err: &str) -> String {
    format!("{source}: Validation errors occurred while attempting a NRTMv4 client update: {err}")
}

/// `RPSLMirrorImportUpdateRunner.run`: an `OSError`.
pub fn mirror_os_error(source: &str, ose: &str) -> String {
    format!(
        "An error occurred while attempting a mirror update or initial import for {source}: {ose}"
    )
}

/// `RPSLMirrorImportUpdateRunner.run`: any other exception.
pub fn mirror_exception(source: &str, exc: &str) -> String {
    format!(
        "An exception occurred while attempting a mirror update or initial import for {source}: {exc}"
    )
}

/// `run_full_or_nrtm3_import` (debug). The values are Python reprs.
pub fn mirror_status(
    source: &str,
    serial_newest_mirror: &str,
    force_reload: &str,
    nrtm_enabled: &str,
) -> String {
    format!(
        "Most recent mirrored serial for {source}: {serial_newest_mirror}, force_reload: \
         {force_reload}, nrtm enabled: {nrtm_enabled}"
    )
}

/// `RPSLMirrorFullImportRunner.run`: no `import_source`.
pub fn skipping_full_import(source: &str) -> String {
    format!("Skipping full RPSL import for {source}, import_source not set.")
}

/// `RPSLMirrorFullImportRunner.run`: start. Both values are Python
/// reprs/strs (a list and a string or `None`).
pub fn running_full_import(
    source: &str,
    import_sources: &str,
    import_serial_source: &str,
) -> String {
    format!(
        "Running full RPSL import of {source} from {import_sources}, serial from {import_serial_source}"
    )
}

/// `RPSLMirrorFullImportRunner.run`: the export is not newer.
pub fn full_import_cancelled(
    source: &str,
    serial_newest_mirror: i64,
    import_serial: i64,
) -> String {
    format!(
        "Current newest serial seen from mirror for {source} is {serial_newest_mirror}, \
         import_serial is {import_serial}, cancelling import."
    )
}

/// `NRTMImportUpdateStreamRunner.run` (debug).
pub fn skipping_nrtm(source: &str) -> String {
    format!("Skipping NRTM updates for {source}, nrtm_host not set.")
}

/// `NRTMImportUpdateStreamRunner.run`.
pub fn retrieving_nrtm(source: &str, serial_start: i64, host: &str, port: i64) -> String {
    format!("Retrieving NRTM updates for {source} from serial {serial_start} on {host}:{port}")
}

/// `NRTMImportUpdateStreamRunner.run` (debug).
pub fn received_nrtm(source: &str, response: &str) -> String {
    format!("Received NRTM response for {source}: {response}")
}

// irrd/mirroring/parsers.py, NRTMStreamParser

/// No `%END` as the last comment.
pub fn nrtm_no_end(source: &str, last_comment: &str) -> String {
    format!(
        "NRTM stream error for {source}: last comment paragraph expected to be \"%END {source}\", \
         but is actually \"{last_comment}\" - could be caused by TCP disconnection during NRTM \
         query or mirror server returning an error or an otherwise incomplete or invalid response"
    )
}

/// More operations than the START line's range.
pub fn nrtm_too_many_operations(source: &str, last_serial: i64, current_op_serial: i64) -> String {
    format!(
        "NRTM stream error for {source}: expected operations up to and including serial \
         {last_serial}, last operation was {current_op_serial}"
    )
}

/// A second START line.
pub fn nrtm_second_start(source: &str, first_serial: i64, last_serial: i64, line: &str) -> String {
    format!(
        "Encountered second START line in NRTM stream, first was {source} {first_serial}-{last_serial}, \
         new line is: {line}"
    )
}

/// The START line names another source.
pub fn nrtm_invalid_source(source: &str, nrtm_source: &str, line: &str) -> String {
    format!(
        "Invalid NRTM source in START line: expected {source} but found {nrtm_source} in line: {line}"
    )
}

/// The START line has a version other than 1 or 3.
pub fn nrtm_invalid_version(version: &str, line: &str) -> String {
    format!("Invalid NRTM version {version} in START line: {line}")
}

/// A valid START line (debug).
pub fn nrtm_valid_start(source: &str, first_serial: i64, last_serial: i64) -> String {
    format!("Found valid start line for {source}, range {first_serial}-{last_serial}")
}

/// An ADD/DEL before the START line.
pub fn nrtm_operation_before_start(paragraph: &str) -> String {
    format!(
        "Encountered operation before valid NRTM START line, paragraph encountered: {paragraph}"
    )
}

/// An ADD/DEL serial lower than expected.
pub fn nrtm_invalid_serial(source: &str, line_serial: i64, current_op_serial: i64) -> String {
    format!(
        "Invalid NRTM serial for {source}: ADD/DEL has serial {line_serial}, expected at least \
         {current_op_serial}"
    )
}

// irrd/mirroring/nrtm_operation.py

/// `NRTMOperation.__repr__`.
pub fn nrtm_operation_repr(source: &str, origin_identifier: &str, operation: &str) -> String {
    format!("{source}/{origin_identifier}/{operation}")
}

/// An unknown object class (info).
pub fn ignoring_nrtm_operation(op: &str, exc: &str) -> String {
    format!("Ignoring NRTM operation {op}: {exc}")
}

/// Parser errors (critical).
pub fn nrtm_operation_parsing_errors(op: &str, errors: &str, object_text: &str) -> String {
    format!(
        "Parsing errors occurred while processing NRTM operation {op}. This operation is ignored, \
         causing potential data inconsistencies. A new operation for this update, without errors, \
         will still be processed and cause the inconsistency to be resolved. Parser error \
         messages: {errors}; original object text follows:\n{object_text}"
    )
}

/// The object's source is not the stream's (critical, and the mirror error).
pub fn nrtm_incorrect_source(
    source: &str,
    obj_source: &str,
    origin_identifier: &str,
    operation: &str,
    pk: &str,
) -> String {
    format!(
        "Incorrect source in NRTM object: stream has source {source}, found object with source \
         {obj_source} in operation {origin_identifier}/{operation}/{pk}. This operation is ignored, \
         causing potential data inconsistencies."
    )
}

/// A saved operation (info), without the RPKI part.
pub fn completed_nrtm_operation(op: &str, object_class: &str, rpsl_pk: &str) -> String {
    format!("Completed NRTM operation {op}/{object_class}/{rpsl_pk}")
}

/// The RPKI part of the completed line.
pub fn completed_rpki_status(status: &str) -> String {
    format!(", RPKI status {status}")
}

// irrd/mirroring/retrieval.py

/// `retrieve_file`: unsupported scheme.
pub fn invalid_url_scheme(url: &str, scheme: &str) -> String {
    format!("Invalid URL: {url} - scheme {scheme} is not supported")
}

/// A download into memory (info).
pub fn downloaded(url: &str) -> String {
    format!("Downloaded {url}")
}

/// A download into a file (info).
pub fn downloaded_to(url: &str, name: &str) -> String {
    format!("Downloaded (and gunzipped if applicable) {url} to {name}")
}

/// A local gzipped file (debug).
pub fn local_gunzip(path: &str) -> String {
    format!("Local file is expected to be gzipped, gunzipping from {path}")
}

/// A failed download; `detail` is the error, or `status: body`.
pub fn failed_to_download(url: &str, detail: &str) -> String {
    format!("Failed to download {url}: {detail}")
}

/// `check_file_hash_sha256`.
pub fn invalid_hash(filename: &str, expected: &str, found: &str) -> String {
    format!("Invalid hash in {filename}: expected {expected}, found {found}")
}

/// `bytes.fromhex()` on a bad character.
pub fn fromhex_error(position: usize) -> String {
    format!("non-hexadecimal number found in fromhex() arg at position {position}")
}

/// `UnicodeDecodeError` from `bytes.decode("utf-8")`.
pub fn utf8_decode_error(byte: u8, position: usize, reason: &str) -> String {
    format!("'utf-8' codec can't decode byte 0x{byte:02x} in position {position}: {reason}")
}

/// `gzip.BadGzipFile`.
pub fn not_gzipped(magic_repr: &str) -> String {
    format!("Not a gzipped file ({magic_repr})")
}

/// `EOFError` from gzip on a truncated file.
pub const GZIP_EOF: &str = "Compressed file ended before the end-of-stream marker was reached";

// irrd/utils/whois_client.py and the socket module

/// `whois_query` (debug).
pub fn running_whois_query(query: &str, host: &str, port: u16) -> String {
    format!("Running whois query {query} on {host} port {port}")
}

/// `whois_query`: no data within the timeout (warning).
pub fn whois_query_timed_out(query: &str, host: &str, port: u16) -> String {
    format!("Whois query {query} timed out on {host} port {port}")
}

/// `socket.timeout`.
pub const TIMED_OUT: &str = "timed out";

/// `socket.gaierror` for an unknown name (glibc's `EAI_NONAME`).
pub const GAI_NONAME: &str = "[Errno -2] Name or service not known";

/// `socket.gaierror` when no name server answers (`EAI_AGAIN`).
pub const GAI_AGAIN: &str = "[Errno -3] Temporary failure in name resolution";

// irrd/mirroring/nrtm4/nrtm4_client.py

/// Snapshot loaded, deltas wait for the next run (#1087).
pub fn nrtm4_deferring_deltas(source: &str, version: i64) -> String {
    format!("{source}: Loaded snapshot at version {version}, deferring deltas to next run")
}

/// Deltas to load.
pub fn nrtm4_updating_from_deltas(source: &str, version: i64) -> String {
    format!("{source}: Updating from deltas, starting from version {version}")
}

/// Nothing to do.
pub fn nrtm4_up_to_date(source: &str, version: i64) -> String {
    format!("{source}: Up to date at version {version}")
}

/// The UNF was signed with the next key.
pub fn nrtm4_key_rotated(source: &str, old: &str, new: &str) -> String {
    format!("{source}: Update Notification File signing key rotated from {old} to {new}")
}

/// Only the configured initial key verifies the UNF.
pub fn nrtm4_signature_config_key_only(
    source: &str,
    config_key: &str,
    current_key: &str,
    msg_next_key: &str,
) -> String {
    format!(
        "{source}: No valid signature found for the Update Notification File. The signature is \
         valid for public key {config_key} set in the nrtm4_client_initial_public_key setting, but \
         that is only used for initial validation. IRRD is currently expecting the public key \
         {current_key}{msg_next_key}. If you want to clear IRRDs key information and revert to \
         nrtm4_client_initial_public_key, use the 'irrdctl nrtm4 client-clear-known-keys' command."
    )
}

/// The `" or {next_key}"` part of the message above.
pub fn nrtm4_msg_next_key(next_key: &str) -> String {
    format!(" or {next_key}")
}

/// One key's failure in the message below.
pub fn nrtm4_key_attempt(key_escaped: &str, error: &str) -> String {
    format!("; attempting '{key_escaped}' resulted in error: '{error}'")
}

/// No key verifies the UNF.
pub fn nrtm4_no_valid_signature(source: &str, attempts: &str) -> String {
    format!("{source}: No valid signature found for any known keys{attempts}")
}

/// `force_reload` is set.
pub fn nrtm4_forced_reload(source: &str) -> String {
    format!("{source}: Forced reload flag set, reloading from snapshot")
}

/// Nothing known yet.
pub fn nrtm4_no_previous(source: &str) -> String {
    format!("{source}: No previous known session ID or version, reloading from snapshot")
}

/// A new session on the server.
pub fn nrtm4_session_changed(source: &str, old: &str, new: &str) -> String {
    format!("{source}: Session ID has changed from {old} to {new}, reloading from snapshot")
}

/// The UNF is older than what was already loaded.
pub fn nrtm4_unf_older(
    source: &str,
    session_id: &str,
    unf_version: i64,
    last_version: i64,
) -> String {
    format!(
        "Update Notification File {source}/{session_id} has matching session ID, but version \
         {unf_version} is older than local version {last_version}"
    )
}

/// The deltas needed are gone from the server.
pub fn nrtm4_deltas_unavailable(source: &str, last_version: i64) -> String {
    format!(
        "{source}: Deltas from current version {last_version} not available on server, reloading \
         from snapshot"
    )
}

/// A file reference changed between UNFs.
pub fn nrtm4_rewriting_history(
    source: &str,
    reference: &str,
    current_name: &str,
    current_hash: &str,
    previous_name: &str,
    previous_hash: &str,
) -> String {
    format!(
        "{source}: Reference {reference} has filename '{current_name}' with hash '{current_hash}' \
         in current Update Notification File, but had filename '{previous_name}' with hash \
         '{previous_hash}' in a previous Update Notification File. Server is rewriting history."
    )
}

/// The snapshot import report prefix.
pub fn nrtm4_snapshot_prefix(source: &str, version: i64) -> String {
    format!("{source}: import of snapshot at version {version}")
}

/// A delta with only a header.
pub fn nrtm4_empty_delta(source: &str, session_id: &str, version: i64) -> String {
    format!("Delta file {source}/{session_id}/{version} did not contain any entries.")
}

/// A delta entry missing a key; `ke` is `str(KeyError)`, `item` the
/// entry's Python repr.
pub fn nrtm4_invalid_delta_entry(
    source: &str,
    session_id: &str,
    version: i64,
    ke: &str,
    item: &str,
) -> String {
    format!("Delta file {source}/{session_id}/{version} contained invalid entry: {ke}: {item}")
}

// irrd/mirroring/nrtm4/nrtm4_types.py

/// `origin_identifier` of a snapshot.
pub fn nrtm4_snapshot_origin(session_id: &str, version: i64) -> String {
    format!("{session_id}/S{version}")
}

/// `origin_identifier` of a delta.
pub fn nrtm4_delta_origin(session_id: &str, version: i64) -> String {
    format!("{session_id}/D{version}")
}

/// `check_version_consistency`.
pub fn nrtm4_unf_version_inconsistent(version: i64, expected: i64) -> String {
    format!(
        "Update Notification File version {version} should have version {expected} based on \
         Snapshot and Delta versions"
    )
}

/// `check_version_consistency`: a gap in the deltas.
pub const NRTM4_DELTAS_NOT_CONTIGUOUS: &str =
    "Deltas in Update Notification File do not have contiguous serials.";

/// `validate_timestamp`.
pub fn nrtm4_unf_too_old(isoformat: &str) -> String {
    format!("Update Notification File is older than 24 hours, timestamp {isoformat}")
}

/// `validate_next_signing_key`.
pub fn nrtm4_invalid_next_signing_key(key: &str, ve: &str) -> String {
    format!("Update Notification File has invalid next_signing_key {key}: {ve}")
}

/// `validate_expected_values`.
pub fn nrtm4_mismatch(key: &str, expected: &str, value: &str) -> String {
    format!("Mismatch in {key} field: expected {expected}, found {value}")
}

// irrd/mirroring/scheduler.py

/// `run_if_relevant` (debug).
pub fn started_scheduled_process(process_name: &str, source: Option<&str>) -> String {
    match source {
        Some(s) => {
            format!("Started new scheduled process {process_name} for mirror import/export for {s}")
        }
        None => format!("Started new scheduled process {process_name}"),
    }
}

/// `terminate_children`.
pub const SCHEDULER_TERMINATING: &str = "MirrorScheduler terminating children";

/// `NRTMOperation.__init__` with neither text nor key.
pub const NRTM_OPERATION_TEXT_OR_PK: &str = "Operation must have object text or pk/class";

/// `OverflowError` from the socket module for a port out of range.
pub const PORT_RANGE: &str = "getsockaddrarg: port must be 0-65535.";

/// `requests`: `REQUESTS_CA_BUNDLE` names nothing usable.
pub fn invalid_ca_bundle(path: &str) -> String {
    format!("Could not find a suitable TLS CA certificate bundle, invalid path: {path}")
}
