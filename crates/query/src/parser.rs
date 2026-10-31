//! A port of `WhoisQueryParser` (`irrd/server/whois/query_parser.py`): one
//! [`WhoisSession`] per whois connection (or per HTTP request), holding the
//! state that persists across queries (`!!`/`-k`, `!s`/`-s`, `!e`, `!f`,
//! `!t`, `-T`).

use std::collections::VecDeque;
use std::sync::Arc;

use store::{ReadView, Store};

use crate::messages;
use crate::nrtm::{NrtmRequest, NrtmV3};
use crate::resolver::{
    Found, QResult, QueryError, QueryResolver, RouteLookupType, invalid, ipy, write_prefix,
};
use crate::response::{Response, ResponseMode, ResponseType};
use crate::settings::{QuerySettings, RPKI_IRR_PSEUDO_SOURCE};

/// `SOCKET_DEFAULT_TIMEOUT`
pub const SOCKET_DEFAULT_TIMEOUT: u64 = 30;

const LOG_TARGET: &str = "irrd.server.whois.query_parser";

/// One whois session.
pub struct WhoisSession {
    /// `multiple_command_mode` (`!!`, `-k`).
    pub multiple_command_mode: bool,
    /// Read timeout in seconds (`!t`).
    pub timeout: u64,
    key_fields_only: bool,
    excluded_sets: Vec<String>,
    client_ip: String,
    client_str: String,
    resolver: QueryResolver,
    nrtm: Arc<dyn NrtmV3>,
    /// The result text of the last query.
    result: String,
}

impl std::fmt::Debug for WhoisSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhoisSession")
            .field("client", &self.client_str)
            .finish_non_exhaustive()
    }
}

/// What a query should do with the output it produced.
enum Out {
    /// `result = None`
    None,
    /// `result` is the text in the session buffer.
    Text,
}

impl WhoisSession {
    /// A new session for a client (`client_str` is `ip:port`).
    pub fn new(
        settings: Arc<QuerySettings>,
        nrtm: Arc<dyn NrtmV3>,
        client_ip: &str,
        client_str: &str,
    ) -> Self {
        WhoisSession {
            multiple_command_mode: false,
            timeout: SOCKET_DEFAULT_TIMEOUT,
            key_fields_only: false,
            excluded_sets: Vec::new(),
            client_ip: client_ip.to_owned(),
            client_str: client_str.to_owned(),
            resolver: QueryResolver::new(settings),
            nrtm,
            result: String::new(),
        }
    }

    /// The resolver (source selection, filters).
    pub fn resolver(&self) -> &QueryResolver {
        &self.resolver
    }

    /// The result text of the last query, before `clean_response()`.
    pub fn result(&self) -> &str {
        &self.result
    }

    /// Mutable access to the result text (for `clean_response()`).
    pub(crate) fn result_mut(&mut self) -> &mut String {
        &mut self.result
    }

    /// `handle_query()`: run one query against the store. The result text
    /// is left in [`WhoisSession::result`].
    pub fn handle_query(&mut self, store: &Store, query: &str) -> Response {
        self.key_fields_only = false;
        self.result.clear();

        if query.contains('\0') {
            self.result.push_str(messages::NULL_BYTES);
            return Response::new(ResponseType::ErrorUser, ResponseMode::Irrd);
        }

        #[cfg(feature = "fault-injection")]
        if query == "!~panic" {
            panic!("fault injection");
        }

        let mut query = query;
        if let Some(rest) = query.strip_prefix("-V ") {
            // query.split(" ", 2): exactly three parts, or ValueError.
            if let Some((user_agent, remainder)) = rest.split_once(' ')
                && remainder.starts_with('!')
            {
                query = remainder;
                self.handle_user_agent(user_agent);
            }
        }

        let tx = match store.read() {
            Ok(tx) => tx,
            Err(e) => {
                let mode = if query.starts_with('!') {
                    ResponseMode::Irrd
                } else {
                    ResponseMode::Ripe
                };
                return self.internal_error(query, &e.to_string(), mode);
            }
        };
        let view = tx.view();

        if let Some(cmd) = query.strip_prefix('!') {
            return match self.handle_irrd_command(&view, cmd) {
                Ok(r) => r,
                Err(QueryError::Invalid(msg)) => {
                    tracing::info!(target: LOG_TARGET, "{}", messages::log_parsing_error(&self.client_str, query, &msg));
                    self.result.clear();
                    self.result.push_str(&msg);
                    Response::new(ResponseType::ErrorUser, ResponseMode::Irrd)
                }
                Err(QueryError::Internal(e)) => self.internal_error(query, &e, ResponseMode::Irrd),
            };
        }

        match self.handle_ripe_command(&view, query) {
            Ok(r) => r,
            Err(QueryError::Invalid(msg)) => {
                tracing::info!(target: LOG_TARGET, "{}", messages::log_parsing_error(&self.client_str, query, &msg));
                self.result.clear();
                self.result.push_str(&msg);
                Response::new(ResponseType::ErrorUser, ResponseMode::Ripe)
            }
            Err(QueryError::Internal(e)) => self.internal_error(query, &e, ResponseMode::Ripe),
        }
    }

    fn internal_error(&mut self, query: &str, e: &str, mode: ResponseMode) -> Response {
        tracing::error!(target: LOG_TARGET, "{}", messages::log_exception(query, e));
        self.result.clear();
        self.result.push_str(messages::INTERNAL_ERROR);
        Response::new(ResponseType::ErrorInternal, mode)
    }

    fn handle_irrd_command(
        &mut self,
        view: &ReadView<'_>,
        full_command: &str,
    ) -> QResult<Response> {
        let mut chars = full_command.chars();
        let Some(command) = chars.next() else {
            return invalid(messages::MISSING_IRRD_COMMAND.to_owned());
        };
        let parameter = chars.as_str();
        let mut cmd_buf = [0u8; 4];
        let command_str: &str = command.encode_utf8(&mut cmd_buf);

        if "tg6ijmnors".contains(command) && parameter.is_empty() {
            return invalid(messages::missing_parameter(command_str));
        }

        let upper = rpsl::python::upper(full_command);
        let mut response_type = ResponseType::Success;
        let mut out = Out::Text;
        let not_found_if_empty = |s: &Self, t: &mut ResponseType| {
            if s.result.is_empty() {
                *t = ResponseType::KeyNotFound;
            }
        };

        if command == '!' {
            self.multiple_command_mode = true;
            out = Out::None;
            response_type = ResponseType::NoResponse;
        } else if upper == "FNO-RPKI-FILTER" {
            self.resolver.disable_rpki_filter();
            self.result.push_str(messages::RPKI_FILTER_DISABLED);
        } else if upper == "FNO-SCOPE-FILTER" {
            self.resolver.disable_out_of_scope_filter();
            self.result.push_str(messages::SCOPE_FILTER_DISABLED);
        } else if upper == "FNO-ROUTE-PREFERENCE-FILTER" {
            self.resolver.disable_route_preference_filter();
            self.result
                .push_str(messages::ROUTE_PREFERENCE_FILTER_DISABLED);
        } else {
            match command {
                'v' => {
                    let v = messages::version(&self.resolver.settings().version);
                    self.result.push_str(&v);
                }
                't' => {
                    self.handle_irrd_timeout_update(parameter)?;
                    out = Out::None;
                }
                'g' | '6' => {
                    self.routes_for_origin(view, parameter, if command == 'g' { 4 } else { 6 })?;
                    not_found_if_empty(self, &mut response_type);
                }
                'a' => {
                    self.handle_irrd_routes_for_as_set(view, parameter)?;
                    not_found_if_empty(self, &mut response_type);
                }
                'i' => {
                    self.handle_irrd_set_members(view, parameter)?;
                    not_found_if_empty(self, &mut response_type);
                }
                'j' => self.handle_irrd_database_serial_range(view, parameter)?,
                'J' => self.handle_irrd_database_status(view, parameter)?,
                'm' => {
                    self.handle_irrd_exact_key(view, parameter)?;
                    not_found_if_empty(self, &mut response_type);
                }
                'n' => {
                    self.handle_user_agent(parameter);
                    out = Out::None;
                }
                'o' => {
                    self.handle_inverse_attr_search(view, "mnt-by", parameter)?;
                    not_found_if_empty(self, &mut response_type);
                }
                'r' => {
                    self.handle_irrd_route_search(view, parameter)?;
                    not_found_if_empty(self, &mut response_type);
                }
                's' => {
                    if !self.handle_irrd_sources_list(parameter)? {
                        out = Out::None;
                    }
                }
                'e' => {
                    if !self.handle_irrd_set_exclusion(parameter) {
                        out = Out::None;
                    }
                }
                _ => return invalid(messages::unrecognised_command(command_str)),
            }
        }
        if matches!(out, Out::None) {
            self.result.clear();
        }
        Ok(Response::new(response_type, ResponseMode::Irrd))
    }

    fn handle_irrd_timeout_update(&mut self, timeout: &str) -> QResult<()> {
        match rpsl::python::int(timeout) {
            Some(v) if v > 0 && v <= 1000 => {
                self.timeout = v as u64;
                Ok(())
            }
            _ => invalid(messages::invalid_timeout(timeout)),
        }
    }

    fn routes_for_origin(&mut self, view: &ReadView<'_>, origin: &str, version: u8) -> QResult<()> {
        let asdot = self.resolver.settings().asdot_queries;
        let (formatted, _) = match rpsl::parse_as_number(origin, false, true, asdot) {
            Ok(v) => v,
            Err(e) => return invalid(e),
        };
        let prefixes = self
            .resolver
            .routes_for_origin(view, &formatted, Some(version))?;
        self.write_prefixes(&prefixes);
        Ok(())
    }

    fn write_prefixes(&mut self, prefixes: &[(u8, u128, u8)]) {
        for (i, (v, a, l)) in prefixes.iter().enumerate() {
            if i > 0 {
                self.result.push(' ');
            }
            write_prefix(&mut self.result, *v, *a, *l);
        }
    }

    fn handle_irrd_routes_for_as_set(
        &mut self,
        view: &ReadView<'_>,
        set_name: &str,
    ) -> QResult<()> {
        let (set_name, version) = if let Some(s) = set_name.strip_prefix('4') {
            (s, Some(4))
        } else if let Some(s) = set_name.strip_prefix('6') {
            (s, Some(6))
        } else {
            (set_name, None)
        };
        if set_name.is_empty() {
            return invalid(messages::MISSING_SET_NAME.to_owned());
        }
        let prefixes =
            self.resolver
                .routes_for_as_set(view, set_name, version, &self.excluded_sets)?;
        self.write_prefixes(&prefixes);
        Ok(())
    }

    fn handle_irrd_set_members(&mut self, view: &ReadView<'_>, parameter: &str) -> QResult<()> {
        let (parameter, recursive) = match parameter.strip_suffix(",1") {
            Some(p) => (p, true),
            None => (parameter, false),
        };
        let members = self.resolver.members_for_set(
            view,
            parameter,
            &self.excluded_sets,
            0,
            recursive,
            None,
        )?;
        for (i, m) in members.iter().enumerate() {
            if i > 0 {
                self.result.push(' ');
            }
            self.result.push_str(m);
        }
        Ok(())
    }

    fn handle_irrd_database_serial_range(
        &mut self,
        view: &ReadView<'_>,
        parameter: &str,
    ) -> QResult<()> {
        let settings = self.resolver.settings();
        let sources: Vec<String> = if parameter == "-*" {
            settings
                .all_valid_real_sources()
                .map(str::to_owned)
                .collect()
        } else {
            parameter
                .split(',')
                .map(|s| rpsl::python::upper(s).into_owned())
                .collect()
        };
        let invalid_sources: Vec<&String> = sources
            .iter()
            .filter(|s| !settings.is_valid_real_source(s))
            .collect();
        let rows = QueryResolver::status_rows(view, &sources)?;
        let mut text = String::new();
        for row in rows {
            let source = rpsl::python::upper(&row.source);
            let keep_journal = if settings.source(&source).keep_journal.truthy() {
                "Y"
            } else {
                "N"
            };
            text.push_str(&source);
            text.push(':');
            text.push_str(keep_journal);
            text.push(':');
            match row.serial_newest_mirror {
                Some(n) if n != 0 => {
                    text.push_str("0-");
                    text.push_str(&n.to_string());
                }
                _ => text.push('-'),
            }
            if let Some(e) = row.serial_last_export
                && e != 0
            {
                text.push(':');
                text.push_str(&e.to_string());
            }
            text.push('\n');
        }
        for s in invalid_sources {
            text.push_str(&messages::database_unknown(&rpsl::python::upper(s)));
            text.push('\n');
        }
        self.result.push_str(rpsl::python::strip(&text));
        Ok(())
    }

    fn handle_irrd_database_status(&mut self, view: &ReadView<'_>, parameter: &str) -> QResult<()> {
        let sources = if parameter == "-*" {
            None
        } else {
            Some(
                parameter
                    .split(',')
                    .map(|s| rpsl::python::upper(s).into_owned())
                    .collect(),
            )
        };
        let json = crate::status::database_status_json(&self.resolver, view, sources)?;
        self.result.push_str(&json);
        Ok(())
    }

    fn handle_irrd_exact_key(&mut self, view: &ReadView<'_>, parameter: &str) -> QResult<()> {
        let Some((object_class, rpsl_pk)) = parameter.split_once(',') else {
            return invalid(messages::invalid_object_lookup(parameter));
        };
        let pk_owned;
        let rpsl_pk = if object_class == "route" || object_class == "route6" {
            pk_owned = rpsl::python::upper(rpsl_pk).replace([' ', '-'], "");
            pk_owned.as_str()
        } else {
            rpsl_pk
        };
        let found = self.resolver.key_lookup(view, object_class, rpsl_pk)?;
        self.flatten(&found);
        Ok(())
    }

    fn handle_irrd_route_search(&mut self, view: &ReadView<'_>, parameter: &str) -> QResult<()> {
        let (address, option) = if parameter.contains(',') {
            let mut parts = parameter.split(',');
            let a = parts.next().unwrap_or_default();
            let o = parts.next().unwrap_or_default();
            if parts.next().is_some() {
                // `address, option = parameter.split(",")`
                return Err(QueryError::Internal(
                    "too many values to unpack (expected 2)".to_owned(),
                ));
            }
            (a, Some(o))
        } else {
            (parameter, None)
        };
        let Some(ip) = ipy(address) else {
            return invalid(messages::invalid_route_search_input(parameter));
        };
        let lookup = match option {
            None | Some("o") => RouteLookupType::Exact,
            Some("l") => RouteLookupType::LessSpecificOneLevel,
            Some("L") => RouteLookupType::LessSpecificWithExact,
            Some("M") => RouteLookupType::MoreSpecificWithoutExact,
            Some(other) => return invalid(messages::invalid_route_search_option(other)),
        };
        let found = self.resolver.route_search(view, &ip, lookup)?;
        if option == Some("o") {
            for (i, (_, o)) in found.iter().enumerate() {
                if i > 0 {
                    self.result.push(' ');
                }
                let origin = crate::resolver::parsed_field(o.parsed_data, "origin");
                if let Some(v) = origin.first() {
                    self.result.push_str(v);
                }
            }
            return Ok(());
        }
        self.flatten(&found);
        Ok(())
    }

    /// Returns whether there is a result.
    fn handle_irrd_sources_list(&mut self, parameter: &str) -> QResult<bool> {
        if parameter == "-*" {
            return Ok(false);
        }
        if parameter == "-lc" {
            let joined = self.resolver.sources().join(",");
            self.result.push_str(&joined);
            return Ok(true);
        }
        let sources = rpsl::python::upper(parameter)
            .split(',')
            .map(str::to_owned)
            .collect();
        self.resolver.set_query_sources(Some(sources))?;
        Ok(false)
    }

    /// Returns whether there is a result.
    fn handle_irrd_set_exclusion(&mut self, parameter: &str) -> bool {
        if parameter == "-lc" {
            self.result.push_str(&self.excluded_sets.join(","));
            return true;
        }
        self.excluded_sets = if parameter.is_empty() {
            Vec::new()
        } else {
            rpsl::python::upper(parameter)
                .split(',')
                .map(str::to_owned)
                .collect()
        };
        false
    }

    fn handle_ripe_command(&mut self, view: &ReadView<'_>, full_query: &str) -> QResult<Response> {
        // re.sub(" +", " ", full_query).strip().split(" ")
        let mut collapsed = String::with_capacity(full_query.len());
        let mut prev_space = false;
        for c in full_query.chars() {
            if c == ' ' {
                if !prev_space {
                    collapsed.push(' ');
                }
                prev_space = true;
            } else {
                collapsed.push(c);
                prev_space = false;
            }
        }
        let mut components: VecDeque<&str> = rpsl::python::strip(&collapsed).split(' ').collect();
        let mut response_type = ResponseType::Success;
        let mut remove_auth_hashes = true;
        let mut has_result = false;

        while let Some(component) = components.pop_front() {
            let Some(command) = component.strip_prefix('-') else {
                self.result.clear();
                self.handle_ripe_text_search(view, component)?;
                has_result = true;
                continue;
            };
            let missing = || QueryError::Invalid(messages::missing_argument(command));
            match command {
                "k" => self.multiple_command_mode = true,
                "l" | "L" | "M" | "x" => {
                    let arg = components.pop_front().ok_or_else(missing)?;
                    self.result.clear();
                    self.handle_ripe_route_search(view, command, arg)?;
                    has_result = true;
                    if self.result.is_empty() {
                        response_type = ResponseType::KeyNotFound;
                    }
                    break;
                }
                "i" => {
                    let attr = components.pop_front().ok_or_else(missing)?;
                    let value = components.pop_front().ok_or_else(missing)?;
                    self.result.clear();
                    self.handle_inverse_attr_search(view, attr, value)?;
                    has_result = true;
                    if self.result.is_empty() {
                        response_type = ResponseType::KeyNotFound;
                    }
                    break;
                }
                "s" => {
                    let arg = components.pop_front().ok_or_else(missing)?;
                    let sources = rpsl::python::upper(arg)
                        .split(',')
                        .map(str::to_owned)
                        .collect();
                    self.resolver.set_query_sources(Some(sources))?;
                }
                "a" => self.resolver.set_query_sources(None)?,
                "T" => {
                    let arg = components.pop_front().ok_or_else(missing)?;
                    self.resolver.set_object_class_filter_next_query(
                        arg.split(',').map(str::to_owned).collect(),
                    );
                }
                "t" => {
                    let arg = components.pop_front().ok_or_else(missing)?;
                    self.result.clear();
                    match rpsl::class_by_name(arg) {
                        Some(c) => self.result.push_str(&c.generate_template()),
                        None => return invalid(messages::unknown_object_class(arg)),
                    }
                    has_result = true;
                    break;
                }
                "K" => self.key_fields_only = true,
                "V" => {
                    let arg = components.pop_front().ok_or_else(missing)?;
                    self.handle_user_agent(arg);
                }
                "q" => {
                    let arg = components.pop_front().ok_or_else(missing)?;
                    self.result.clear();
                    self.handle_nrtm_information_query(view, arg)?;
                    has_result = true;
                }
                "g" => {
                    let arg = components.pop_front().ok_or_else(missing)?;
                    self.result.clear();
                    self.handle_nrtm_request(view, arg)?;
                    has_result = true;
                    remove_auth_hashes = false;
                }
                "F" | "r" => {}
                _ => return invalid(messages::unrecognised_flag(command)),
            }
        }
        if !has_result {
            self.result.clear();
        }
        let mut r = Response::new(response_type, ResponseMode::Ripe);
        r.remove_auth_hashes = remove_auth_hashes;
        Ok(r)
    }

    fn handle_ripe_route_search(
        &mut self,
        view: &ReadView<'_>,
        command: &str,
        parameter: &str,
    ) -> QResult<()> {
        let Some(ip) = ipy(parameter) else {
            return invalid(messages::invalid_route_search_input(parameter));
        };
        let lookup = match command {
            "x" => RouteLookupType::Exact,
            "l" => RouteLookupType::LessSpecificOneLevel,
            "L" => RouteLookupType::LessSpecificWithExact,
            _ => RouteLookupType::MoreSpecificWithoutExact,
        };
        let found = self.resolver.route_search(view, &ip, lookup)?;
        self.flatten(&found);
        Ok(())
    }

    fn handle_ripe_text_search(&mut self, view: &ReadView<'_>, value: &str) -> QResult<()> {
        let found = self.resolver.rpsl_text_search(view, value)?;
        self.flatten(&found);
        Ok(())
    }

    fn handle_user_agent(&mut self, user_agent: &str) {
        self.resolver.user_agent = Some(user_agent.to_owned());
        tracing::info!(target: LOG_TARGET, "{}", messages::log_user_agent(&self.client_str, user_agent));
    }

    fn handle_nrtm_information_query(&mut self, view: &ReadView<'_>, param: &str) -> QResult<()> {
        if param != "sources" {
            return invalid(messages::unrecognised_parameter(param));
        }
        let settings = self.resolver.settings();
        let rows = QueryResolver::status_rows(view, &settings.sources)?;
        let mut text = String::new();
        for row in rows {
            let source = rpsl::python::upper(&row.source).into_owned();
            let s = settings.source(&source);
            let permitted = |list: &Option<String>| {
                settings
                    .is_client_permitted(&self.client_ip, list.as_deref(), true)
                    .unwrap_or(false)
            };
            let permission =
                if !permitted(&s.nrtm_access_list) && !permitted(&s.nrtm_access_list_unfiltered) {
                    "N"
                } else {
                    "X"
                };
            let range = match (row.serial_oldest_journal, row.serial_newest_journal) {
                (Some(o), Some(n)) if o != 0 && n != 0 => format!("{o}-{n}"),
                _ => "Unknown".to_owned(),
            };
            text.push_str(&format!("{source}:3:{permission}:{range}\n"));
        }
        self.result.push_str(rpsl::python::strip(&text));
        Ok(())
    }

    fn handle_nrtm_request(&mut self, view: &ReadView<'_>, param: &str) -> QResult<()> {
        let parts: Vec<&str> = param.split(':').collect();
        let [source, version, serial_range] = parts[..] else {
            return invalid(messages::NRTM_THREE_ELEMENTS.to_owned());
        };
        let bad_range = || QueryError::Invalid(messages::invalid_serial_range(serial_range));
        let range_parts: Vec<&str> = serial_range.split('-').collect();
        let [start, end] = range_parts[..] else {
            return Err(bad_range());
        };
        let serial_start = rpsl::python::int(start).ok_or_else(bad_range)?;
        let serial_end = if end == "LAST" {
            None
        } else {
            Some(rpsl::python::int(end).ok_or_else(bad_range)?)
        };
        if version != "1" && version != "3" {
            return invalid(messages::invalid_nrtm_version(version));
        }
        let source = rpsl::python::upper(source).into_owned();
        let settings = self.resolver.settings();
        if !settings.is_valid_real_source(&source) {
            return invalid(messages::unknown_source(&source));
        }
        let s = settings.source(&source);
        let permitted = |list: &Option<String>| {
            settings
                .is_client_permitted(&self.client_ip, list.as_deref(), true)
                .unwrap_or(false)
        };
        let in_list = permitted(&s.nrtm_access_list);
        let in_unfiltered = permitted(&s.nrtm_access_list_unfiltered);
        if !in_list && !in_unfiltered {
            return invalid(messages::ACCESS_DENIED.to_owned());
        }
        let clamp = |v: i128| v.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
        let request = NrtmRequest {
            source: &source,
            version,
            serial_start: clamp(serial_start),
            serial_end: serial_end.map(clamp),
            remove_auth_hashes: !in_unfiltered,
            client_is_dummifying_exempt: in_unfiltered,
        };
        let text = crate::nrtm::generate(&*self.nrtm, settings, view, &request)?;
        self.result.push_str(&text);
        Ok(())
    }

    fn handle_inverse_attr_search(
        &mut self,
        view: &ReadView<'_>,
        attribute: &str,
        value: &str,
    ) -> QResult<()> {
        let found = self
            .resolver
            .rpsl_attribute_search(view, attribute, value)?;
        self.flatten(&found);
        Ok(())
    }

    /// `_flatten_query_output()`
    fn flatten(&mut self, found: &[Found<'_>]) {
        if self.key_fields_only {
            self.filter_key_fields(found);
        } else {
            self.flatten_objects(found);
        }
        let out = &mut self.result;
        let end = out.trim_end_matches(['\n', '\r']).len();
        out.truncate(end);
        let start = out.len() - out.trim_start_matches(['\n', '\r']).len();
        if start > 0 {
            out.drain(..start);
        }
    }

    fn flatten_objects(&mut self, found: &[Found<'_>]) {
        let rpki_aware = self.resolver.rpki_aware;
        let out = &mut self.result;
        for (_, obj) in found {
            out.push_str(obj.object_text);
            if rpki_aware
                && obj.source != RPKI_IRR_PSEUDO_SOURCE
                && (obj.object_class == "route" || obj.object_class == "route6")
            {
                out.push_str("rpki-ov-state:  ");
                out.push_str(obj.rpki_status.pg_label());
                if obj.rpki_status == store::RpkiStatus::NotFound {
                    out.push_str(messages::RPKI_NOT_FOUND_COMMENT);
                }
                out.push('\n');
            }
            out.push('\n');
        }
    }

    /// `_filter_key_fields()`
    fn filter_key_fields(&mut self, found: &[Found<'_>]) {
        let mut results: Vec<String> = Vec::new();
        for (_, obj) in found {
            let Some(class) = rpsl::class_by_name(obj.object_class) else {
                continue;
            };
            let parsed = crate::resolver::parsed_value(obj.parsed_data);
            let mut result = String::new();
            for field in class.pk_fields().chain(["members", "mp-members"]) {
                match parsed.get(field) {
                    Some(serde_json::Value::Array(items)) if !items.is_empty() => {
                        for item in items {
                            result.push_str(field);
                            result.push_str(": ");
                            push_py_str(&mut result, item);
                            result.push('\n');
                        }
                    }
                    Some(v) if json_truthy(v) && !v.is_array() => {
                        result.push_str(field);
                        result.push_str(": ");
                        push_py_str(&mut result, v);
                        result.push('\n');
                    }
                    _ => {}
                }
            }
            if !results.contains(&result) {
                results.push(result);
            }
        }
        self.result.push_str(&results.join("\n"));
    }
}

fn json_truthy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Object(o) => !o.is_empty(),
    }
}

/// `f"{value}"` of a JSON value as Python would print it.
fn push_py_str(out: &mut String, v: &serde_json::Value) {
    match v {
        serde_json::Value::String(s) => out.push_str(s),
        serde_json::Value::Bool(true) => out.push_str("True"),
        serde_json::Value::Bool(false) => out.push_str("False"),
        serde_json::Value::Null => out.push_str("None"),
        other => out.push_str(&other.to_string()),
    }
}
