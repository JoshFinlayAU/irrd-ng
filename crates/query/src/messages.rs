//! User-facing strings, copied verbatim from IRRd v4 at the pinned baseline.
//!
//! Every message a client, operator or mail recipient can see lives here, so a
//! parity fix to wording touches exactly one place. Sources are
//! `irrd/server/whois/query_parser.py`, `query_response.py`, `server.py`,
//! `irrd/server/query_resolver.py`, `irrd/server/access_check.py`,
//! `irrd/server/http/endpoints_api.py` and `irrd/mirroring/nrtm_generator.py`
//! (see also `parity/reference/v4-strings.tsv`).

// ---- query_parser.py ----

/// `handle_query`: a NUL byte anywhere in the query.
pub const NULL_BYTES: &str = "Queries may not contain null bytes";
/// Any exception that is not an `InvalidQueryException`.
pub const INTERNAL_ERROR: &str = "An internal error occurred while processing this query.";
/// `!` with nothing after it.
pub const MISSING_IRRD_COMMAND: &str = "Missing IRRD command";

/// `Missing parameter for {command} query`
pub fn missing_parameter(command: &str) -> String {
    format!("Missing parameter for {command} query")
}

/// `!fno-rpki-filter`
pub const RPKI_FILTER_DISABLED: &str = "Filtering out RPKI invalids is disabled for !r and RIPE style queries for the rest of this connection.";
/// `!fno-scope-filter`
pub const SCOPE_FILTER_DISABLED: &str = "Filtering out out-of-scope objects is disabled for !r and RIPE style queries for the rest of this connection.";
/// `!fno-route-preference-filter`
pub const ROUTE_PREFERENCE_FILTER_DISABLED: &str = "Filtering out objects suppressed due to route preference is disabled for !r and RIPE style queries for the rest of this connection.";

/// `Unrecognised command: {command}`
pub fn unrecognised_command(command: &str) -> String {
    format!("Unrecognised command: {command}")
}

/// `Invalid value for timeout: {timeout}`
pub fn invalid_timeout(timeout: &str) -> String {
    format!("Invalid value for timeout: {timeout}")
}

/// `!a` without a set name.
pub const MISSING_SET_NAME: &str = "Missing required set name for A query";

/// `X:Database unknown` line of `!j`.
pub fn database_unknown(source: &str) -> String {
    format!("{source}:X:Database unknown")
}

/// `Invalid argument for object lookup: {parameter}`
pub fn invalid_object_lookup(parameter: &str) -> String {
    format!("Invalid argument for object lookup: {parameter}")
}

/// `Invalid input for route search: {parameter}`
pub fn invalid_route_search_input(parameter: &str) -> String {
    format!("Invalid input for route search: {parameter}")
}

/// `Invalid route search option: {option}`
pub fn invalid_route_search_option(option: &str) -> String {
    format!("Invalid route search option: {option}")
}

/// `IRRd -- version {__version__}`
pub fn version(v: &str) -> String {
    format!("IRRd -- version {v}")
}

/// `Unrecognised flag/search: {command}`
pub fn unrecognised_flag(command: &str) -> String {
    format!("Unrecognised flag/search: {command}")
}

/// `Missing argument for flag/search: {command}`
pub fn missing_argument(command: &str) -> String {
    format!("Missing argument for flag/search: {command}")
}

/// `Unrecognised parameter: {param}` (`-q`)
pub fn unrecognised_parameter(param: &str) -> String {
    format!("Unrecognised parameter: {param}")
}

/// `-g` with other than three `:`-separated elements.
pub const NRTM_THREE_ELEMENTS: &str = "Invalid parameter: must contain three elements";

/// `Invalid serial range: {serial_range}`
pub fn invalid_serial_range(range: &str) -> String {
    format!("Invalid serial range: {range}")
}

/// `Invalid NRTM version: {version}`
pub fn invalid_nrtm_version(version: &str) -> String {
    format!("Invalid NRTM version: {version}")
}

/// `Unknown source: {source}`
pub fn unknown_source(source: &str) -> String {
    format!("Unknown source: {source}")
}

/// NRTM access refused.
pub const ACCESS_DENIED: &str = "Access denied";

/// Log: `{client_str}: encountered parsing error while parsing query "{query}": {exc}`
pub fn log_parsing_error(client: &str, query: &str, exc: &str) -> String {
    format!("{client}: encountered parsing error while parsing query \"{query}\": {exc}")
}

/// Log: `An exception occurred while processing whois query "{query}": {exc}`
pub fn log_exception(query: &str, exc: &str) -> String {
    format!("An exception occurred while processing whois query \"{query}\": {exc}")
}

/// Log: `{client_str}: user agent set to: {user_agent}`
pub fn log_user_agent(client: &str, ua: &str) -> String {
    format!("{client}: user agent set to: {ua}")
}

// ---- query_response.py ----

/// The RIPE-style empty answer.
pub const RIPE_NO_ENTRIES: &str = "%  No entries found for the selected source(s).\n\n\n";

// ---- query_resolver.py ----

/// `set_query_sources()` with an unknown source.
pub const SOURCES_UNAVAILABLE: &str = "One or more selected sources are unavailable.";

/// `rpsl_attribute_search()` with an unsupported attribute (v4's text has
/// no space after the comma).
pub fn inverse_not_supported(attribute: &str, names: &str) -> String {
    format!(
        "Inverse attribute search not supported for {attribute},only supported for attributes: {names}"
    )
}

/// `Unknown object class: {object_class}`
pub fn unknown_object_class(class: &str) -> String {
    format!("Unknown object class: {class}")
}

/// `!J` entry of an unknown source.
pub const UNKNOWN_SOURCE_JSON: &str = "Unknown source";

/// `rpki-ov-state` comment for `not_found`.
pub const RPKI_NOT_FOUND_COMMENT: &str =
    " # No ROAs found, or RPKI validation not enabled for source";

// ---- nrtm_generator.py ----

/// No journal for the source.
pub const NRTM_NO_JOURNAL: &str = "No journal kept for this source, unable to serve NRTM queries";
/// No `database_status` row.
pub const NRTM_NO_ENTRIES: &str = "There are no journal entries for this source.";

/// `Start of the serial range ({start}) must be lower or equal to end of the serial range ({end})`
pub fn nrtm_start_after_end(start: i64, end: i64) -> String {
    format!(
        "Start of the serial range ({start}) must be lower or equal to end of the serial range ({end})"
    )
}

/// The journal is empty.
pub const NRTM_NO_UPDATES: &str = "% Warning: there are no updates available";
/// Starting right after the newest serial, up to LAST.
pub const NRTM_NO_NEWER_UPDATES: &str = "% Warning: there are no newer updates available";

/// `Serials {a} - {b} do not exist`
pub fn nrtm_serials_missing(a: i64, b: i64) -> String {
    format!("Serials {a} - {b} do not exist")
}

/// `Serial range requested exceeds maximum range of {range_limit}`
pub fn nrtm_range_exceeded(range_limit: &str) -> String {
    format!("Serial range requested exceeds maximum range of {range_limit}")
}

/// `There are no journal entries greater than or equal to this serial {start}.`
pub fn nrtm_no_entries_from(start: i64) -> String {
    format!("There are no journal entries greater than or equal to this serial {start}.")
}

/// `Requesting serials older than {days_limit} days will be rejected`
pub fn nrtm_too_old(days_limit: &str) -> String {
    format!("Requesting serials older than {days_limit} days will be rejected")
}

// ---- server.py ----

/// Sent (without a newline) to a client outside the access list.
pub const WHOIS_ACCESS_DENIED: &[u8] = b"%% Access denied";

/// Log: `Starting whois server on TCP {address}`, with Python's tuple repr.
pub fn log_starting_whois(interface: &str, port: u16) -> String {
    format!("Starting whois server on TCP ('{interface}', {port})")
}

/// Log: `{client_str}: sent answer to query, elapsed {elapsed:.9f}s, {n} bytes: {query}`
pub fn log_sent_answer(client: &str, elapsed: f64, n: usize, query: &str) -> String {
    format!("{client}: sent answer to query, elapsed {elapsed:.9}s, {n} bytes: {query}")
}

/// Log: `{client_str}: processing query: {query}`
pub fn log_processing(client: &str, query: &str) -> String {
    format!("{client}: processing query: {query}")
}

/// Log: `{client_str}: closed connection per request`
pub fn log_closed_per_request(client: &str) -> String {
    format!("{client}: closed connection per request")
}

/// Log: `{client_str}: auto-closed connection`
pub fn log_auto_closed(client: &str) -> String {
    format!("{client}: auto-closed connection")
}

/// Log: `Failed to handle whois connection, traceback follows: {e}`
pub fn log_failed_connection(e: &str) -> String {
    format!("Failed to handle whois connection, traceback follows: {e}")
}

// ---- access_check.py ----

/// Log: `Rejecting request, IP not in access list {name}: {client_ip}`
pub fn log_not_in_access_list(name: &str, ip: &str) -> String {
    format!("Rejecting request, IP not in access list {name}: {ip}")
}

/// Log: `Rejecting request, access list empty or undefined: {client_ip}`
pub fn log_access_list_empty(ip: &str) -> String {
    format!("Rejecting request, access list empty or undefined: {ip}")
}

/// Log: `Rejecting request as client IP could not be read from {ip}: {e}`
pub fn log_unreadable_client(ip: &str, e: &str) -> String {
    format!("Rejecting request as client IP could not be read from {ip}: {e}")
}

// ---- endpoints_api.py ----

/// `/v1/whois/` without `q`.
pub const HTTP_MISSING_Q: &str = "Missing required query parameter \"q\"";

/// Log: `{client_str}: sent answer to HTTP query, elapsed {elapsed:.9f}s, {length} chars: {query}`
pub fn log_sent_http_answer(client: &str, elapsed: f64, n: usize, query: &str) -> String {
    format!("{client}: sent answer to HTTP query, elapsed {elapsed:.9}s, {n} chars: {query}")
}
