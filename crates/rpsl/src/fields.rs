//! RPSL field types: a port of `irrd/rpsl/fields.py`.
//!
//! Each field parses one normalised attribute value (comments stripped,
//! continuation lines joined with commas), records INFO/ERROR messages
//! exactly as v4 does, and returns the parsed value plus any metadata the
//! value carries (addresses, prefix, AS numbers).

use crate::classes;
use crate::ipy::{self, Ip};
use crate::messages;
use crate::parser_state::Messages;
use crate::py;
use crate::settings::{PasswordHasher, RpslSettings};
use crate::validators::{parse_as_number, strptime_ymd};

/// `RPSL_MNTNER_AUTH_INTERNAL` (`irrd/conf/__init__.py`).
pub const RPSL_MNTNER_AUTH_INTERNAL: &str = "IRRD-INTERNAL-AUTH";
/// `PASSWORD_HASH_DUMMY_VALUE` (`irrd/conf/__init__.py`).
pub const PASSWORD_HASH_DUMMY_VALUE: &str = "DummyValue";
/// `BCRYPT_MAX_ROUNDS` (`irrd/conf/__init__.py`).
pub const BCRYPT_MAX_ROUNDS: u32 = 16;

const RESERVED_WORDS: [&str; 20] = [
    "ANY", "AS-ANY", "RS_ANY", "PEERAS", "AND", "OR", "NOT", "ATOMIC", "FROM", "TO", "AT",
    "ACTION", "ACCEPT", "ANNOUNCE", "EXCEPT", "REFINE", "NETWORKS", "INTO", "INBOUND", "OUTBOUND",
];
const RESERVED_PREFIXES: [&str; 5] = ["AS-", "RS-", "RTRS-", "FLTR-", "PRNG-"];

/// The kind of an RPSL field, with its per-field options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// `RPSLTextField`
    Text,
    /// `RPSLIPv4PrefixField`
    Ipv4Prefix,
    /// `RPSLIPv4PrefixesField`
    Ipv4Prefixes,
    /// `RPSLIPv6PrefixField`
    Ipv6Prefix,
    /// `RPSLIPv6PrefixesField`
    Ipv6Prefixes,
    /// `RPSLIPv4AddressRangeField`
    Ipv4AddressRange,
    /// `RPSLRouteSetMembersField(ip_version=...)`, 0 meaning any version.
    RouteSetMembers {
        /// IP version members must have, or 0.
        ip_version: u8,
    },
    /// `RPSLASNumberField`
    AsNumber,
    /// `RPSLASBlockField`
    AsBlock,
    /// `RPSLSetNameField(prefix=...)`; `prefix` includes the trailing hyphen.
    SetName {
        /// For example `"AS-"`.
        prefix: &'static str,
    },
    /// `RPSLEmailField`
    Email,
    /// `RPSLChangedField`
    Changed,
    /// `RPSLDNSNameField`
    DnsName,
    /// `RPSLURLField`
    Url,
    /// `RPSLGenericNameField`
    GenericName {
        /// Reserved prefixes this field permits, with hyphen (e.g. `"AS-"`).
        allowed_prefixes: &'static [&'static str],
        /// Accept anything in non-strict mode (nic-hdl).
        non_strict_allow_any: bool,
    },
    /// `RPSLReferenceField`
    Reference {
        /// Object classes this field refers to.
        referring: &'static [&'static str],
        /// Whether the reference is checked on updates.
        strong: bool,
    },
    /// `RPSLReferenceListField`
    ReferenceList {
        /// Object classes this field refers to.
        referring: &'static [&'static str],
        /// Whether the reference is checked on updates.
        strong: bool,
        /// Accept the keyword `ANY` instead of a list.
        allow_kw_any: bool,
    },
    /// `RPSLAuthField`
    Auth,
}

impl FieldKind {
    /// v4's `keep_case`: if false, parsed values are upper-cased.
    pub fn keep_case(&self) -> bool {
        !matches!(
            self,
            FieldKind::SetName { .. }
                | FieldKind::DnsName
                | FieldKind::Url
                | FieldKind::GenericName { .. }
                | FieldKind::Reference { .. }
                | FieldKind::ReferenceList { .. }
        )
    }

    /// Classes referred to, for reference fields.
    pub fn referring(&self) -> &'static [&'static str] {
        match self {
            FieldKind::Reference { referring, .. } | FieldKind::ReferenceList { referring, .. } => {
                referring
            }
            _ => &[],
        }
    }

    /// Whether this is a strong reference field.
    pub fn strong(&self) -> bool {
        match self {
            FieldKind::Reference { strong, .. } | FieldKind::ReferenceList { strong, .. } => {
                *strong
            }
            _ => false,
        }
    }
}

/// One attribute definition on an object class.
#[derive(Debug, Clone, Copy)]
pub struct FieldDef {
    /// Attribute name.
    pub name: &'static str,
    /// Field type.
    pub kind: FieldKind,
    /// May be absent.
    pub optional: bool,
    /// May occur more than once.
    pub multiple: bool,
    /// Part of the primary key.
    pub primary_key: bool,
    /// Indexed for lookups.
    pub lookup_key: bool,
}

/// `RPSLFieldParseResult`.
#[derive(Debug, Clone, Default)]
pub(crate) struct FieldParseResult {
    pub(crate) value: String,
    pub(crate) values_list: Option<Vec<String>>,
    pub(crate) ip_first: Option<Ip>,
    pub(crate) ip_last: Option<Ip>,
    pub(crate) prefix: Option<Ip>,
    pub(crate) prefix_length: Option<u32>,
    pub(crate) asn_first: Option<u32>,
    pub(crate) asn_last: Option<u32>,
}

impl FieldParseResult {
    fn value(value: String) -> Self {
        FieldParseResult {
            value,
            ..Default::default()
        }
    }
}

/// A parse failure that v4 does not catch: the `ValueError` propagates out
/// of the object constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Uncaught(pub(crate) String);

pub(crate) type FieldResult = Result<Option<FieldParseResult>, Uncaught>;

pub(crate) struct ParseCtx<'s> {
    pub(crate) strict: bool,
    pub(crate) settings: &'s RpslSettings,
}

impl FieldDef {
    pub(crate) fn parse(
        &self,
        value: &str,
        messages: &mut Messages,
        ctx: &ParseCtx<'_>,
    ) -> FieldResult {
        parse_kind(&self.kind, value, messages, ctx)
    }
}

fn parse_kind(
    kind: &FieldKind,
    value: &str,
    messages: &mut Messages,
    ctx: &ParseCtx<'_>,
) -> FieldResult {
    let strict = ctx.strict;
    Ok(match kind {
        FieldKind::Text => Some(FieldParseResult::value(strip_nonprintable(value))),
        FieldKind::Ipv4Prefix => parse_ip_prefix(value, messages, 4),
        FieldKind::Ipv6Prefix => parse_ip_prefix(value, messages, 6),
        FieldKind::Ipv4Prefixes => {
            return parse_list(value, messages, |v, m| Ok(parse_ip_prefix(v, m, 4)));
        }
        FieldKind::Ipv6Prefixes => {
            return parse_list(value, messages, |v, m| Ok(parse_ip_prefix(v, m, 6)));
        }
        FieldKind::Ipv4AddressRange => parse_address_range(value, messages),
        FieldKind::RouteSetMembers { ip_version } => {
            return parse_list(value, messages, |v, m| {
                Ok(parse_route_set_member(v, m, *ip_version, strict))
            });
        }
        FieldKind::AsNumber => parse_as_number_field(value, messages),
        FieldKind::AsBlock => parse_as_block(value, messages),
        FieldKind::SetName { prefix } => parse_set_name(&[prefix], value, messages, strict),
        FieldKind::Email => {
            if is_email(value) {
                Some(FieldParseResult::value(value.to_owned()))
            } else {
                messages.error(messages::invalid_email(value));
                None
            }
        }
        FieldKind::Changed => parse_changed(value, messages),
        FieldKind::DnsName => {
            if is_dns_name(value) {
                Some(FieldParseResult::value(value.to_owned()))
            } else {
                messages.error(messages::invalid_dns_name(value));
                None
            }
        }
        FieldKind::Url => return parse_url(value, messages),
        FieldKind::GenericName {
            allowed_prefixes,
            non_strict_allow_any,
        } => parse_generic_name(
            value,
            messages,
            strict,
            allowed_prefixes,
            *non_strict_allow_any,
        ),
        FieldKind::Reference { referring, .. } => {
            return parse_reference(referring, value, messages, ctx);
        }
        FieldKind::ReferenceList {
            referring,
            allow_kw_any,
            ..
        } => {
            if *allow_kw_any && py::upper(value) == "ANY" {
                return Ok(Some(FieldParseResult {
                    value: "ANY".to_owned(),
                    values_list: Some(vec!["ANY".to_owned()]),
                    ..Default::default()
                }));
            }
            return parse_list(value, messages, |v, m| {
                parse_reference(referring, v, m, ctx)
            });
        }
        FieldKind::Auth => parse_auth(value, messages, ctx),
    })
}

/// `value.translate(NOPRINT_TRANS_TABLE)`: drop every character that is not
/// printable, except newline, carriage return, tab and zero width joiner.
pub(crate) fn strip_nonprintable(value: &str) -> String {
    let keep = |c: char| py::is_printable(c) || matches!(c, '\n' | '\r' | '\t' | '\u{200d}');
    if value.chars().all(keep) {
        return value.to_owned();
    }
    value.chars().filter(|&c| keep(c)).collect()
}

/// `RPSLFieldListMixin.parse`.
fn parse_list<F>(value: &str, messages: &mut Messages, mut single: F) -> FieldResult
where
    F: FnMut(&str, &mut Messages) -> FieldResult,
{
    let mut values = Vec::new();
    let mut all_ok = true;
    for single_value in value.split(',') {
        let single_value = py::strip(single_value);
        if single_value.is_empty() {
            continue;
        }
        match single(single_value, messages)? {
            Some(r) => values.push(r.value),
            None => all_ok = false,
        }
    }
    if !all_ok {
        return Ok(None);
    }
    Ok(Some(FieldParseResult {
        value: values.join(","),
        values_list: Some(values),
        ..Default::default()
    }))
}

fn is_ipv4_prefix_syntax(value: &str) -> bool {
    // ^\d+\.\d+\.\d+\.\d+/\d+$
    let value = value.strip_suffix('\n').unwrap_or(value);
    let Some((addr, len)) = value.split_once('/') else {
        return false;
    };
    let digits = |s: &str| !s.is_empty() && s.chars().all(py::is_re_digit);
    let parts: Vec<&str> = addr.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| digits(p)) && digits(len)
}

fn is_ipv6_prefix_syntax(value: &str) -> bool {
    // ^[A-F\d:]+/\d+$ with IGNORECASE
    let value = value.strip_suffix('\n').unwrap_or(value);
    let Some((addr, len)) = value.split_once('/') else {
        return false;
    };
    !addr.is_empty()
        && addr
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || py::is_re_digit(c))
        && !len.is_empty()
        && len.chars().all(py::is_re_digit)
}

/// `RPSLIPv4PrefixField` / `RPSLIPv6PrefixField`.
fn parse_ip_prefix(value: &str, messages: &mut Messages, version: u8) -> Option<FieldParseResult> {
    let syntax_ok = if version == 4 {
        is_ipv4_prefix_syntax(value)
    } else {
        is_ipv6_prefix_syntax(value)
    };
    if !syntax_ok {
        messages.error(messages::invalid_prefix(value));
        return None;
    }
    let ip = match Ip::parse(value, version) {
        Ok(ip) => ip,
        Err(e) => {
            messages.error(messages::invalid_prefix_detail(
                value,
                &ipy::clean_ip_value_error(&e.0),
            ));
            return None;
        }
    };
    let mut parsed = ip.to_string();
    let full = if version == 4 { 32 } else { 128 };
    if ip.prefixlen() == full {
        parsed.push_str(if version == 4 { "/32" } else { "/128" });
    }
    if parsed != value {
        messages.info(messages::prefix_reformatted(value, &parsed));
    }
    Some(FieldParseResult {
        value: parsed,
        ip_first: Some(ip.net()),
        ip_last: Some(ip.broadcast()),
        prefix: Some(ip),
        prefix_length: Some(ip.prefixlen()),
        ..Default::default()
    })
}

/// `RPSLIPv4AddressRangeField`.
fn parse_address_range(value: &str, messages: &mut Messages) -> Option<FieldParseResult> {
    let value = value.replace(',', "");
    let (ip1_input, ip2_input) = value.split_once('-').unwrap_or((&value, &value));
    let parsed = Ip::parse(ip1_input, 0).and_then(|ip1| Ok((ip1, Ip::parse(ip2_input, 0)?)));
    let (ip1, ip2) = match parsed {
        Ok(v) => v,
        Err(e) => {
            messages.error(messages::invalid_range_detail(
                &value,
                &ipy::clean_ip_value_error(&e.0),
            ));
            return None;
        }
    };
    if !(ip1.version() == 4 && ip2.version() == 4) {
        messages.error(messages::invalid_range_version(&value));
        return None;
    }
    if ip1.int() > ip2.int() {
        messages.error(messages::invalid_range_order(&value));
        return None;
    }
    let parsed_value = if value.contains('-') {
        format!("{ip1} - {ip2}")
    } else {
        ip1.to_string()
    };
    if parsed_value != value {
        messages.info(messages::range_reformatted(&value, &parsed_value));
    }
    Some(FieldParseResult {
        value: parsed_value,
        ip_first: Some(ip1),
        ip_last: Some(ip2),
        ..Default::default()
    })
}

struct RangeOperator<'a> {
    start: Option<&'a str>,
    end: Option<&'a str>,
    single: Option<&'a str>,
}

/// `re_range_operator`:
/// `^(?P<start>\d{1,3})-(?P<end>\d{1,3})$|^(-)$|^(\+)$|^(?P<single>\d{1,3})$`
fn match_range_operator(op: &str) -> Option<RangeOperator<'_>> {
    let body = op.strip_suffix('\n').unwrap_or(op);
    let digits13 = |s: &str| {
        let n = s.chars().count();
        (1..=3).contains(&n) && s.chars().all(py::is_re_digit)
    };
    if let Some((a, b)) = body.split_once('-')
        && digits13(a)
        && digits13(b)
    {
        return Some(RangeOperator {
            start: Some(a),
            end: Some(b),
            single: None,
        });
    }
    if body == "-" || body == "+" {
        return Some(RangeOperator {
            start: None,
            end: None,
            single: None,
        });
    }
    if digits13(body) {
        return Some(RangeOperator {
            start: None,
            end: None,
            single: Some(body),
        });
    }
    None
}

fn small_int(s: &str) -> i128 {
    py::parse_int(s, 10)
        .ok()
        .and_then(|v| v.to_i128())
        .unwrap_or(0)
}

/// `RPSLRouteSetMemberField.parse`.
fn parse_route_set_member(
    value: &str,
    messages: &mut Messages,
    ip_version: u8,
    strict: bool,
) -> Option<FieldParseResult> {
    let (address, range_operator) = match value.split_once('^') {
        Some((a, op)) => {
            if op.is_empty() {
                messages.error(messages::missing_range_operator(value));
                return None;
            }
            (a, op)
        }
        None => (value, ""),
    };

    let mut set_messages = Messages::default();
    let set_result = parse_set_name(&["RS-", "AS-"], address, &mut set_messages, strict);
    if let Some(r) = set_result
        && !set_messages.has_errors()
    {
        let mut result_value = r.value;
        if !range_operator.is_empty() {
            result_value.push('^');
            result_value.push_str(range_operator);
        }
        if result_value != value {
            messages.info(messages::route_set_member_reformatted(value, &result_value));
        }
        return Some(FieldParseResult::value(result_value));
    }
    if let Ok((parsed_str, _)) = parse_as_number(address, false, false, false) {
        let mut result_value = parsed_str;
        if !range_operator.is_empty() {
            result_value.push('^');
            result_value.push_str(range_operator);
        }
        if result_value != value {
            messages.info(messages::route_set_member_reformatted(value, &result_value));
        }
        return Some(FieldParseResult::value(result_value));
    }

    let ip = match Ip::parse(address, ip_version) {
        Ok(ip) => ip,
        Err(e) => {
            messages.error(messages::not_set_name_nor_prefix(
                address,
                &ipy::clean_ip_value_error(&e.0),
            ));
            return None;
        }
    };

    if !range_operator.is_empty() {
        let Some(m) = match_range_operator(range_operator) else {
            messages.error(messages::invalid_range_operator(range_operator, value));
            return None;
        };
        let prefixlen = i128::from(ip.prefixlen());
        if let Some(single) = m.single
            && small_int(single) < prefixlen
        {
            messages.error(messages::range_operator_length(
                single,
                ip.prefixlen(),
                value,
            ));
            return None;
        }
        if let Some(start) = m.start
            && small_int(start) < prefixlen
        {
            messages.error(messages::range_operator_start(start, ip.prefixlen(), value));
            return None;
        }
        if let (Some(end), Some(start)) = (m.end, m.start)
            && small_int(end) < small_int(start)
        {
            messages.error(messages::range_operator_end(end, start, value));
            return None;
        }
    }

    let mut parsed = ip.to_string();
    if ip.version() == 4 && ip.prefixlen() == 32 {
        parsed.push_str("/32");
    }
    if ip.version() == 6 && ip.prefixlen() == 128 {
        parsed.push_str("/128");
    }
    if !range_operator.is_empty() {
        parsed.push('^');
        parsed.push_str(range_operator);
    }
    if parsed != value {
        messages.info(messages::route_set_member_reformatted(value, &parsed));
    }
    Some(FieldParseResult::value(parsed))
}

/// `RPSLASNumberField.parse`.
fn parse_as_number_field(value: &str, messages: &mut Messages) -> Option<FieldParseResult> {
    match parse_as_number(value, false, false, false) {
        Ok((parsed, n)) => {
            if parsed != py::upper(value) {
                messages.info(messages::as_number_reformatted(value, &parsed));
            }
            Some(FieldParseResult {
                value: parsed,
                asn_first: Some(n),
                asn_last: Some(n),
                ..Default::default()
            })
        }
        Err(e) => {
            messages.error(e);
            None
        }
    }
}

/// `RPSLASBlockField.parse`.
fn parse_as_block(value: &str, messages: &mut Messages) -> Option<FieldParseResult> {
    let Some((as1_raw, as2_raw)) = value.split_once('-') else {
        messages.error(messages::as_range_no_hyphen(value));
        return None;
    };
    let parsed = parse_as_number(py::strip(as1_raw), false, false, false)
        .and_then(|a| Ok((a, parse_as_number(py::strip(as2_raw), false, false, false)?)));
    let ((as1_str, as1), (as2_str, as2)) = match parsed {
        Ok(v) => v,
        Err(e) => {
            messages.error(e);
            return None;
        }
    };
    if as1 > as2 {
        messages.error(messages::as_range_order(value));
        return None;
    }
    let parsed_value = format!("{as1_str} - {as2_str}");
    if parsed_value != value {
        messages.info(messages::as_range_reformatted(value, &parsed_value));
    }
    Some(FieldParseResult {
        value: parsed_value,
        asn_first: Some(as1),
        asn_last: Some(as2),
        ..Default::default()
    })
}

/// `re_email`:
/// `^[A-Z0-9$!#%&\"*+\/=?^_`{|}~\\.-]+@(([A-Z0-9\\.-]+)|(\[\d+\.\d+\.\d+\.\d+\])|(\[[A-f\d:]+\]))$`
/// with IGNORECASE.
pub(crate) fn is_email(value: &str) -> bool {
    let value = value.strip_suffix('\n').unwrap_or(value);
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    let local_ok = !local.is_empty()
        && local.chars().all(|c| {
            py::re_ic_alpha(c) || c.is_ascii_digit() || "$!#%&\"*+/=?^_`{|}~\\.-".contains(c)
        });
    if !local_ok {
        return false;
    }
    let plain = !domain.is_empty()
        && domain
            .chars()
            .all(|c| py::re_ic_alpha(c) || c.is_ascii_digit() || matches!(c, '\\' | '.' | '-'));
    if plain {
        return true;
    }
    let Some(inner) = domain.strip_prefix('[').and_then(|d| d.strip_suffix(']')) else {
        return false;
    };
    let v4 = {
        let parts: Vec<&str> = inner.split('.').collect();
        parts.len() == 4
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(py::is_re_digit))
    };
    let v6 = !inner.is_empty()
        && inner.chars().all(|c| {
            py::re_ic_alpha(c)
                || matches!(c, '[' | '\\' | ']' | '^' | '_' | '`' | ':')
                || py::is_re_digit(c)
        });
    v4 || v6
}

/// `RPSLChangedField.parse`.
fn parse_changed(value: &str, messages: &mut Messages) -> Option<FieldParseResult> {
    let parts: Vec<&str> = value.split(' ').collect();
    let (email, date) = if parts.len() == 2 {
        (parts[0], Some(parts[1]))
    } else {
        (value, None)
    };
    if !is_email(email) {
        messages.error(messages::invalid_email(email));
        return None;
    }
    if let Some(date) = date.filter(|d| !d.is_empty())
        && let Err(e) = strptime_ymd(date)
    {
        messages.error(messages::invalid_changed_date(date, &e));
        return None;
    }
    Some(FieldParseResult::value(value.to_owned()))
}

/// `re_dnsname` with IGNORECASE.
fn is_dns_name(value: &str) -> bool {
    let value = value.strip_suffix('\n').unwrap_or(value);
    let alnum = |c: char| py::re_ic_alpha(c) || c.is_ascii_digit();
    value.split('.').all(|label| {
        let mut chars = label.chars();
        match (chars.next(), label.chars().last()) {
            (Some(first), Some(last)) => {
                alnum(first) && alnum(last) && label.chars().all(|c| alnum(c) || c == '-')
            }
            _ => false,
        }
    })
}

/// `RPSLURLField.parse`, using the parts of CPython 3.13's `urlsplit` that
/// decide the scheme and netloc.
fn parse_url(value: &str, messages: &mut Messages) -> FieldResult {
    let mut url: String = value
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut scheme = String::new();
    if let Some(i) = url.find(':') {
        let first = url.chars().next();
        if i > 0
            && first.is_some_and(|c| c.is_ascii_alphabetic())
            && url[..i]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            scheme = url[..i].to_ascii_lowercase();
            url = url[i + 1..].to_owned();
        }
    }
    let mut netloc = "";
    if let Some(rest) = url.strip_prefix("//") {
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        netloc = &rest[..end];
        if netloc.contains('[') != netloc.contains(']') {
            return Err(Uncaught("Invalid IPv6 URL".to_owned()));
        }
    }
    if (scheme == "http" || scheme == "https") && !netloc.is_empty() {
        return Ok(Some(FieldParseResult::value(value.to_owned())));
    }
    messages.error(messages::invalid_url("http/https", value));
    Ok(None)
}

/// `re_generic_name`: `^[A-Z][A-Z0-9_-]*[A-Z0-9]$` with IGNORECASE.
pub(crate) fn is_generic_name(value: &str) -> bool {
    let value = value.strip_suffix('\n').unwrap_or(value);
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 2 {
        return false;
    }
    let alnum = |c: char| py::re_ic_alpha(c) || c.is_ascii_digit();
    py::re_ic_alpha(chars[0])
        && alnum(chars[chars.len() - 1])
        && chars[1..chars.len() - 1]
            .iter()
            .all(|&c| alnum(c) || c == '_' || c == '-')
}

/// `RPSLGenericNameField.parse`.
fn parse_generic_name(
    value: &str,
    messages: &mut Messages,
    strict: bool,
    allowed_prefixes: &[&str],
    non_strict_allow_any: bool,
) -> Option<FieldParseResult> {
    if !strict && non_strict_allow_any {
        return Some(FieldParseResult::value(value.to_owned()));
    }
    if strict {
        let upper_value = py::upper(value);
        if RESERVED_WORDS.contains(&upper_value.as_ref()) {
            messages.error(messages::name_reserved_word(value));
            return None;
        }
        for prefix in RESERVED_PREFIXES {
            if upper_value.starts_with(prefix) && !allowed_prefixes.contains(&prefix) {
                messages.error(messages::name_reserved_prefix(value, prefix));
                return None;
            }
        }
    }
    if !is_generic_name(value) {
        messages.error(messages::name_invalid(value));
        return None;
    }
    Some(FieldParseResult::value(value.to_owned()))
}

/// `RPSLReferenceField.parse`: try the primary key field of each referred
/// class in turn; on total failure, report every attempt's messages.
fn parse_reference(
    referring: &[&str],
    value: &str,
    messages: &mut Messages,
    ctx: &ParseCtx<'_>,
) -> FieldResult {
    let mut referring_messages = Messages::default();
    for class in referring {
        let Some(identifier) = classes::identifier_field(class) else {
            continue;
        };
        if let Some(parsed) = parse_kind(&identifier.kind, value, &mut referring_messages, ctx)? {
            return Ok(Some(parsed));
        }
    }
    messages.merge(referring_messages);
    Ok(None)
}

/// `RPSLAuthField.parse`.
fn parse_auth(
    value: &str,
    messages: &mut Messages,
    ctx: &ParseCtx<'_>,
) -> Option<FieldParseResult> {
    let hashers = ctx.settings.password_hashers(!ctx.strict);
    let upper_value = py::upper(value);
    let has_valid_beginning = hashers.iter().any(|h| {
        upper_value
            .strip_prefix(h.scheme())
            .is_some_and(|rest| rest.starts_with(' '))
    });
    let is_valid_hash =
        has_valid_beginning && value.matches(' ').count() == 1 && !value.contains(',');
    if is_valid_hash || is_pgpkey(&upper_value) || value == RPSL_MNTNER_AUTH_INTERNAL {
        let bcrypt_error = if ctx.strict {
            bcrypt_hash_error(value)
        } else {
            None
        };
        if let Some(e) = bcrypt_error {
            messages.error(messages::invalid_auth_detail(value, &e));
            return None;
        }
        return Some(FieldParseResult::value(value.to_owned()));
    }
    let names: Vec<&str> = hashers.iter().map(PasswordHasher::scheme).collect();
    messages.error(messages::invalid_auth(
        value,
        &names.join(", "),
        RPSL_MNTNER_AUTH_INTERNAL,
    ));
    None
}

/// `re_pgpkey`: `^PGPKEY-[A-F0-9]{8}$`, applied to the upper-cased value.
pub(crate) fn is_pgpkey(upper_value: &str) -> bool {
    let v = upper_value.strip_suffix('\n').unwrap_or(upper_value);
    v.strip_prefix("PGPKEY-").is_some_and(|hex| {
        hex.len() == 8
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    })
}

const BCRYPT64: &str = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// `bcrypt_hash_error` (`irrd/rpsl/auth.py`), with passlib 1.7.4's
/// `bcrypt.from_string` acceptance rules.
pub fn bcrypt_hash_error(auth_value: &str) -> Option<String> {
    let (scheme, password_hash) = auth_value.split_once(' ').unwrap_or((auth_value, ""));
    if py::upper(scheme) != "BCRYPT-PW" || password_hash == PASSWORD_HASH_DUMMY_VALUE {
        return None;
    }
    let invalid = || Some(messages::INVALID_BCRYPT_HASH.to_owned());
    let tail = ["$2$", "$2a$", "$2x$", "$2y$", "$2b$"]
        .iter()
        .find_map(|ident| password_hash.strip_prefix(ident).map(|t| (*ident, t)));
    let Some((ident, tail)) = tail else {
        return invalid();
    };
    if ident == "$2x$" {
        return invalid();
    }
    let parts: Vec<&str> = tail.split('$').collect();
    if parts.len() != 2 {
        return invalid();
    }
    let (rounds_str, data) = (parts[0], parts[1]);
    let Some(rounds) = py::parse_int(rounds_str, 10).ok().and_then(|v| v.to_i128()) else {
        return invalid();
    };
    if format!("{rounds:02}") != rounds_str {
        return invalid();
    }
    if !(4..=31).contains(&rounds) {
        return invalid();
    }
    let chars: Vec<char> = data.chars().collect();
    let salt: String = chars.iter().take(22).collect();
    let checksum: String = chars.iter().skip(22).collect();
    if salt.chars().any(|c| !BCRYPT64.contains(c)) || salt.chars().count() != 22 {
        return invalid();
    }
    if !checksum.is_empty()
        && (checksum.chars().any(|c| !BCRYPT64.contains(c)) || checksum.chars().count() != 31)
    {
        return invalid();
    }
    if rounds > i128::from(BCRYPT_MAX_ROUNDS) {
        return Some(messages::bcrypt_cost_too_high(BCRYPT_MAX_ROUNDS));
    }
    None
}

/// `parse_set_name(prefixes, value, messages, strict_validation)`.
pub(crate) fn parse_set_name(
    prefixes: &[&str],
    value: &str,
    messages: &mut Messages,
    strict: bool,
) -> Option<FieldParseResult> {
    let input_components: Vec<&str> = value.split(':').collect();
    let prefix_display = prefixes.join("/");
    let starts_with_prefix = |c: &str| {
        let u = py::upper(c);
        prefixes.iter().any(|p| u.starts_with(p))
    };

    if strict && input_components.len() > 5 {
        messages.error(messages::SET_NAME_TOO_MANY_COMPONENTS.to_owned());
        return None;
    }
    if strict && !input_components.iter().any(|c| starts_with_prefix(c)) {
        messages.error(messages::set_name_no_set_component(value, &prefix_display));
        return None;
    }

    let mut output: Vec<String> = Vec::with_capacity(input_components.len());
    for component in &input_components {
        if strict && RESERVED_WORDS.contains(&py::upper(component).as_ref()) {
            messages.error(messages::set_name_reserved_word(value, component));
            return None;
        }
        let parsed_as_number = parse_as_number(component, false, false, false)
            .ok()
            .map(|(s, _)| s);
        if !is_generic_name(&py::upper(component)) && parsed_as_number.is_none() {
            messages.error(messages::set_component_invalid(value, component));
            return None;
        }
        if strict && parsed_as_number.is_none() && !starts_with_prefix(component) {
            messages.error(messages::set_component_wrong_prefix(
                value,
                component,
                &prefix_display,
            ));
            return None;
        }
        output.push(parsed_as_number.unwrap_or_else(|| (*component).to_owned()));
    }
    let parsed_value = output.join(":");
    if parsed_value != value {
        messages.info(messages::set_name_reformatted(value, &parsed_value));
    }
    Some(FieldParseResult::value(parsed_value))
}
