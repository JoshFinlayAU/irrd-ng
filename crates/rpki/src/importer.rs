//! `irrd/rpki/importer.py`: `ROADataImporter`, `ROA` and
//! `RPSLObjectFromROA`.
//!
//! The JSON is read the way v4 reads it with `ujson`: a root object with a
//! `roas` list of objects carrying `asn`, `prefix`, `maxLength` and `ta`.
//! SLURM (RFC 8416) filters and assertions are applied as v4 applies them.
//! Every check runs in v4's order, so the first problem reported is the one
//! v4 reports, with v4's message.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rpsl::Ip;
use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use store::{IpPrefix, Json, NewRpslObject, RoutePreferenceStatus, RpkiStatus};

use crate::ScopeFilterValidator;
use crate::messages;

/// v4's logger for the importer.
pub const LOG_TARGET: &str = "irrd.rpki.importer";

/// `SLURM_TRUST_ANCHOR`
pub const SLURM_TRUST_ANCHOR: &str = "SLURM file";

/// `RPKI_IRR_PSEUDO_SOURCE`
pub const RPKI_IRR_PSEUDO_SOURCE: &str = store::write::RPKI_IRR_PSEUDO_SOURCE;

/// `RPSL_ATTRIBUTE_TEXT_WIDTH`
const TEXT_WIDTH: usize = 16;

/// Why an import stopped, sorted the way v4's `ROAImportRunner` sorts its
/// exceptions. `Display` is `str(exception)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoaImportError {
    /// `ROAParserException`, already logged by the importer.
    Parser(String),
    /// Any other exception (`TypeError`, `KeyError`, an integrity error).
    Other(String),
}

impl std::fmt::Display for RoaImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoaImportError::Parser(m) | RoaImportError::Other(m) => f.write_str(m),
        }
    }
}

fn parser_error(msg: String) -> RoaImportError {
    tracing::error!(target: LOG_TARGET, "{msg}");
    RoaImportError::Parser(msg)
}

/// A ROA, as v4's `ROA` class holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roa {
    /// `prefix` (an `IPy.IP`).
    pub prefix: Ip,
    /// `str(prefix)`, as IPy prints it.
    pub prefix_str: String,
    /// `asn`
    pub asn: u32,
    /// `int(max_length)`
    pub max_length: i64,
    /// `trust_anchor`
    pub trust_anchor: String,
}

fn ip_addr(ip: &Ip) -> IpAddr {
    if ip.version() == 4 {
        IpAddr::V4(Ipv4Addr::from(ip.int() as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(ip.int()))
    }
}

impl Roa {
    /// The prefix as the store holds it.
    pub fn ip_prefix(&self) -> Option<IpPrefix> {
        IpPrefix::new(ip_addr(&self.prefix), self.prefix.prefixlen() as u8)
    }

    /// `RPSLObjectFromROA.pk()`
    pub fn pseudo_pk(&self) -> String {
        format!("{}AS{}/ML{}", self.prefix_str, self.asn, self.max_length)
    }

    /// `RPSL_ROUTE_OBJECT_CLASS_FOR_IP_VERSION[prefix.version()]`
    pub fn pseudo_class(&self) -> &'static str {
        if self.prefix.version() == 4 {
            "route"
        } else {
            "route6"
        }
    }

    /// `RPSLObjectFromROA.render_rpsl_text()`. `remarks` is the
    /// `rpki.pseudo_irr_remarks` setting.
    pub fn pseudo_text(&self, remarks: &str) -> Result<String, RoaImportError> {
        let class = self.pseudo_class();
        let class_display = format!("{:<width$}", format!("{class}:"), width = TEXT_WIDTH);
        let fill = " ".repeat(TEXT_WIDTH);
        let remarks = remarks.replace('\n', &format!("\n{fill}"));
        let remarks = rpsl::python::strip(&remarks);
        let remarks = py_format(remarks, &self.asn.to_string(), &self.prefix_str)?;
        let text = format!(
            "\n{class_display}{p}\ndescr:          RPKI ROA for {p} / AS{asn}\nremarks:        {remarks}\nmax-length:     {ml}\norigin:         AS{asn}\nsource:         {src}  # Trust Anchor: {ta}\n",
            p = self.prefix_str,
            asn = self.asn,
            ml = self.max_length,
            src = RPKI_IRR_PSEUDO_SOURCE,
            ta = self.trust_anchor,
        );
        Ok(format!("{}\n", rpsl::python::strip(&text)))
    }

    /// The `rpsl_objects` row v4 upserts for the RPKI pseudo-IRR object.
    pub fn pseudo_object(
        &self,
        remarks: &str,
        scopefilter: &ScopeFilterValidator,
    ) -> Result<NewRpslObject, RoaImportError> {
        let class = self.pseudo_class();
        let prefix = self.ip_prefix();
        let mut parsed = serde_json::Map::new();
        parsed.insert(class.to_owned(), self.prefix_str.clone().into());
        parsed.insert("origin".into(), format!("AS{}", self.asn).into());
        parsed.insert("source".into(), RPKI_IRR_PSEUDO_SOURCE.into());
        parsed.insert("rpki_max_length".into(), self.max_length.into());
        let scopefilter_status = scopefilter.validate_rpsl_object(
            RPKI_IRR_PSEUDO_SOURCE,
            class,
            prefix.as_ref(),
            Some(self.asn),
        );
        Ok(NewRpslObject {
            rpsl_pk: self.pseudo_pk(),
            source: RPKI_IRR_PSEUDO_SOURCE.to_owned(),
            object_class: class.to_owned(),
            parsed_data: Json::from_value(&serde_json::Value::Object(parsed)),
            object_text: self.pseudo_text(remarks)?,
            ip_first: Some(ip_addr(&self.prefix.net())),
            ip_last: Some(ip_addr(&self.prefix.broadcast())),
            prefix,
            prefix_length: Some(self.prefix.prefixlen()),
            asn_first: Some(self.asn),
            asn_last: Some(self.asn),
            rpki_status: RpkiStatus::Valid,
            scopefilter_status,
            route_preference_status: RoutePreferenceStatus::Visible,
        })
    }
}

/// `str.format(asn=..., prefix=...)` on the remarks setting: `{asn}`,
/// `{prefix}`, `{{` and `}}`. Any other field is the `KeyError` (or
/// `ValueError`) v4 would raise.
fn py_format(template: &str, asn: &str, prefix: &str) -> Result<String, RoaImportError> {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let mut field = String::new();
                let mut closed = false;
                for f in chars.by_ref() {
                    if f == '}' {
                        closed = true;
                        break;
                    }
                    field.push(f);
                }
                if !closed {
                    return Err(RoaImportError::Other(
                        messages::FORMAT_UNCLOSED_BRACE.to_owned(),
                    ));
                }
                match field.as_str() {
                    "asn" => out.push_str(asn),
                    "prefix" => out.push_str(prefix),
                    other => return Err(RoaImportError::Other(rpsl::python::repr(other))),
                }
            }
            '}' => {
                return Err(RoaImportError::Other(
                    messages::FORMAT_SINGLE_CLOSE_BRACE.to_owned(),
                ));
            }
            c => out.push(c),
        }
    }
    Ok(out)
}

/// One `roas` entry, with each value kept as JSON so v4's per-type
/// behaviour can be reproduced.
#[derive(Debug, Default, Deserialize)]
struct RawRoa {
    asn: Option<serde_json::Value>,
    prefix: Option<serde_json::Value>,
    #[serde(rename = "maxLength")]
    max_length: Option<serde_json::Value>,
    ta: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RawDoc {
    roas: Option<Vec<RawRoa>>,
}

/// `str()` of a JSON value as Python sees it after `ujson.loads`.
fn py_str(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "None".into(),
        serde_json::Value::Bool(true) => "True".into(),
        serde_json::Value::Bool(false) => "False".into(),
        serde_json::Value::Number(n) => py_number(n),
        other => PyValue::from_json(other).repr(),
    }
}

fn py_number(n: &serde_json::Number) -> String {
    if let Some(f) = n.as_f64().filter(|_| n.is_f64()) {
        if f.fract() == 0.0 && f.abs() < 1e16 {
            format!("{f:.1}")
        } else {
            format!("{f}")
        }
    } else {
        n.to_string()
    }
}

fn type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "NoneType",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(n) if n.is_f64() => "float",
        serde_json::Value::Number(_) => "int",
        serde_json::Value::String(_) => "str",
        serde_json::Value::Array(_) => "list",
        serde_json::Value::Object(_) => "dict",
    }
}

/// `parse_as_number(value, permit_plain=True)` for a JSON value.
fn parse_asn(v: &serde_json::Value) -> Result<u32, RoaImportError> {
    match v {
        serde_json::Value::String(s) => rpsl::parse_as_number(s, true, false, false)
            .map(|(_, n)| n)
            .map_err(|e| parser_error(messages::invalid_value_roa_or_slurm(&e))),
        serde_json::Value::Number(n) if !n.is_f64() => match n.as_u64() {
            Some(x) if x <= 4_294_967_295 => Ok(x as u32),
            _ => Err(parser_error(messages::invalid_value_roa_or_slurm(
                &messages::asn_out_of_range(&n.to_string()),
            ))),
        },
        other => Err(RoaImportError::Other(messages::unsupported_value(
            "asn",
            type_name(other),
        ))),
    }
}

/// `IP(value)` for a JSON value.
fn parse_ip(v: &serde_json::Value, what: &str) -> Result<Ip, RoaImportError> {
    match v {
        serde_json::Value::String(s) => {
            Ip::parse(s, 0).map_err(|e| parser_error(messages::invalid_value_roa_or_slurm(&e.0)))
        }
        other => Err(RoaImportError::Other(messages::unsupported_value(
            what,
            type_name(other),
        ))),
    }
}

/// `int(value)` for a JSON value, with Python's error text.
fn py_int(v: &serde_json::Value) -> Result<i64, Result<String, String>> {
    match v {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i)
            } else if let Some(f) = n.as_f64() {
                Ok(f.trunc() as i64)
            } else {
                Err(Err(messages::unsupported_value("maxLength", "int")))
            }
        }
        serde_json::Value::Bool(b) => Ok(i64::from(*b)),
        serde_json::Value::String(s) => match rpsl::python::int(s) {
            Some(i) => i64::try_from(i).map_err(|_| Err(messages::int_too_large())),
            None => Err(Ok(messages::int_invalid_literal(&rpsl::python::repr(s)))),
        },
        other => Err(Err(messages::int_type_error(type_name(other)))),
    }
}

/// Covering checks for SLURM prefix filters: `prefix in IPSet(...)`. An
/// `IPSet` is merged into maximal prefixes, so membership is containment
/// in the union of the filters.
#[derive(Debug, Default, Clone)]
struct IpSet {
    v4: Vec<(u128, u128)>,
    v6: Vec<(u128, u128)>,
}

fn ip_range(ip: &Ip) -> (u128, u128) {
    let bits = if ip.version() == 4 { 32 } else { 128 };
    let host = bits - ip.prefixlen();
    let size_minus_one = if host >= 128 {
        u128::MAX
    } else {
        (1u128 << host) - 1
    };
    (ip.int(), ip.int().saturating_add(size_minus_one))
}

impl IpSet {
    fn add(&mut self, ip: &Ip) {
        let r = ip_range(ip);
        let list = if ip.version() == 4 {
            &mut self.v4
        } else {
            &mut self.v6
        };
        list.push(r);
        list.sort_unstable();
        let mut merged: Vec<(u128, u128)> = Vec::with_capacity(list.len());
        for &(a, b) in list.iter() {
            if let Some(last) = merged.last_mut()
                && (a <= last.1 || a == last.1.saturating_add(1))
            {
                last.1 = last.1.max(b);
                continue;
            }
            merged.push((a, b));
        }
        *list = merged;
    }

    fn contains(&self, ip: &Ip) -> bool {
        let (a, b) = ip_range(ip);
        let list = if ip.version() == 4 {
            &self.v4
        } else {
            &self.v6
        };
        list.iter().any(|&(x, y)| x <= a && b <= y)
    }
}

/// What a ROA source and an optional SLURM file give: v4's
/// `ROADataImporter.roa_objs`, in order.
#[derive(Debug, Clone, Default)]
pub struct RoaImport {
    /// The ROAs to insert, in v4's order (file order, then SLURM
    /// assertions).
    pub roas: Vec<Roa>,
}

#[derive(Default)]
struct Slurm {
    filtered_asns: HashSet<i64>,
    filtered_prefixes: IpSet,
    filtered_combined: HashMap<i64, IpSet>,
    assertions: Vec<RawRoa>,
}

fn json_error_text(e: &serde_json::Error, text: &str) -> String {
    // ujson's messages for the common failures.
    let first = text.trim_start().chars().next();
    match first {
        None => "Expected object or value".to_owned(),
        Some(c) if !matches!(c, '{' | '[' | '"' | '-' | '0'..='9' | 't' | 'f' | 'n') => {
            "Expected object or value".to_owned()
        }
        _ => {
            if e.classify() == serde_json::error::Category::Eof {
                "Expected object or value".to_owned()
            } else if e.to_string().starts_with("trailing characters") {
                "Trailing data".to_owned()
            } else {
                e.to_string()
            }
        }
    }
}

fn load_slurm(text: &str) -> Result<Slurm, RoaImportError> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| RoaImportError::Other(json_error_text(&e, text)))?;
    let version = v.get("slurmVersion");
    if version.and_then(serde_json::Value::as_i64) != Some(1)
        || version.is_some_and(|x| x.is_boolean())
    {
        let shown = version.map_or_else(|| "None".to_owned(), py_str);
        return Err(parser_error(messages::slurm_invalid_version(&shown)));
    }
    let mut s = Slurm::default();
    let int_of = |v: &serde_json::Value| -> Result<i64, RoaImportError> {
        py_int(v).map_err(|e| match e {
            Ok(m) => RoaImportError::Other(m),
            Err(m) => RoaImportError::Other(m),
        })
    };
    let empty = Vec::new();
    let filters = v
        .get("validationOutputFilters")
        .and_then(|f| f.get("prefixFilters"))
        .and_then(serde_json::Value::as_array)
        .unwrap_or(&empty);
    for item in filters {
        let asn = item.get("asn");
        let prefix = item.get("prefix");
        match (asn, prefix) {
            (Some(a), None) => {
                s.filtered_asns.insert(int_of(a)?);
            }
            (None, Some(p)) => {
                let ip = parse_ip_other(p)?;
                s.filtered_prefixes.add(&ip);
            }
            (Some(a), Some(p)) => {
                let a = int_of(a)?;
                let ip = parse_ip_other(p)?;
                s.filtered_combined.entry(a).or_default().add(&ip);
            }
            (None, None) => {}
        }
    }
    let assertions = v
        .get("locallyAddedAssertions")
        .and_then(|f| f.get("prefixAssertions"))
        .and_then(serde_json::Value::as_array)
        .unwrap_or(&empty);
    for a in assertions {
        let prefix = a
            .get("prefix")
            .ok_or_else(|| RoaImportError::Other(rpsl::python::repr("prefix")))?;
        let max_length = match a.get("maxPrefixLength") {
            Some(m) if !m.is_null() => m.clone(),
            _ => serde_json::Value::from(parse_ip_other(prefix)?.prefixlen()),
        };
        let asn = a
            .get("asn")
            .ok_or_else(|| RoaImportError::Other(rpsl::python::repr("asn")))?;
        s.assertions.push(RawRoa {
            asn: Some(serde_json::Value::String(format!("AS{}", py_str(asn)))),
            prefix: Some(prefix.clone()),
            max_length: Some(max_length),
            ta: Some(serde_json::Value::String(SLURM_TRUST_ANCHOR.to_owned())),
        });
    }
    Ok(s)
}

/// `IP(value)` outside the importer's `try`: a `ValueError` here is not
/// turned into a `ROAParserException`.
fn parse_ip_other(v: &serde_json::Value) -> Result<Ip, RoaImportError> {
    match v {
        serde_json::Value::String(s) => Ip::parse(s, 0).map_err(|e| RoaImportError::Other(e.0)),
        other => Err(RoaImportError::Other(messages::unsupported_value(
            "prefix",
            type_name(other),
        ))),
    }
}

impl RoaImport {
    /// `ROADataImporter(rpki_json_str, slurm_json_str)` up to, but not
    /// including, saving: parse, filter and check every ROA. A problem is
    /// logged and returned exactly as v4 raises it.
    pub fn parse(rpki_json: &str, slurm_json: Option<&str>) -> Result<RoaImport, RoaImportError> {
        let doc: RawDoc = match serde_json::from_str(rpki_json) {
            Ok(d) => d,
            Err(e) => {
                if e.classify() == serde_json::error::Category::Data {
                    // Valid JSON of the wrong shape: v4 fails on it with a
                    // TypeError or KeyError of its own.
                    return Err(RoaImportError::Other(e.to_string()));
                }
                return Err(parser_error(messages::invalid_json(&json_error_text(
                    &e, rpki_json,
                ))));
            }
        };
        let Some(mut roa_dicts) = doc.roas else {
            return Err(parser_error(messages::ROOT_KEY_NOT_FOUND.to_owned()));
        };
        let slurm = match slurm_json {
            Some(s) if !s.is_empty() => Some(load_slurm(s)?),
            _ => None,
        };
        let n_file = roa_dicts.len();
        if let Some(s) = &slurm {
            roa_dicts.extend(s.assertions.iter().map(|a| RawRoa {
                asn: a.asn.clone(),
                prefix: a.prefix.clone(),
                max_length: a.max_length.clone(),
                ta: a.ta.clone(),
            }));
        }

        let mut roas = Vec::with_capacity(roa_dicts.len());
        for (idx, d) in roa_dicts.iter().enumerate() {
            let missing = |key: &str| {
                let record = if idx < n_file {
                    record_repr(rpki_json, idx)
                } else {
                    slurm_record_repr(d)
                };
                parser_error(messages::missing_key(&rpsl::python::repr(key), &record))
            };
            let asn = parse_asn(d.asn.as_ref().ok_or_else(|| missing("asn"))?)?;
            let prefix = parse_ip(
                d.prefix.as_ref().ok_or_else(|| missing("prefix"))?,
                "prefix",
            )?;
            let ta = py_str(d.ta.as_ref().ok_or_else(|| missing("ta"))?);
            if ta != SLURM_TRUST_ANCHOR
                && let Some(s) = &slurm
            {
                if s.filtered_asns.contains(&i64::from(asn)) {
                    continue;
                }
                if s.filtered_prefixes.contains(&prefix) {
                    continue;
                }
                if s.filtered_combined
                    .get(&i64::from(asn))
                    .is_some_and(|set| set.contains(&prefix))
                {
                    continue;
                }
            }
            let raw_max = d.max_length.as_ref().ok_or_else(|| missing("maxLength"))?;
            let max_length = match py_int(raw_max) {
                Ok(v) => v,
                Err(Ok(ve)) => return Err(parser_error(messages::invalid_value_in_roa(&ve))),
                Err(Err(other)) => return Err(RoaImportError::Other(other)),
            };
            let prefix_str = prefix.to_string();
            if max_length < i64::from(prefix.prefixlen()) {
                return Err(parser_error(messages::max_length_too_small(
                    prefix.prefixlen(),
                    &py_str(raw_max),
                    &prefix_str,
                    asn,
                )));
            }
            roas.push(Roa {
                prefix,
                prefix_str,
                asn,
                max_length,
                trust_anchor: ta,
            });
        }
        Ok(RoaImport { roas })
    }

    /// v4 inserts each pseudo-IRR object with `rpsl_guaranteed_no_existing`,
    /// so a second ROA with the same prefix, origin and max length (from
    /// another trust anchor, or a repeat) fails the whole import with a
    /// unique violation on `rpsl_objects`. This is the error v4 reports:
    /// the first repeated key in order is the first row that fails in the
    /// flush that fails.
    pub fn first_duplicate(&self) -> Option<&Roa> {
        let mut seen = HashSet::with_capacity(self.roas.len());
        self.roas
            .iter()
            .find(|r| !seen.insert((r.pseudo_class(), r.pseudo_pk())))
    }
}

/// The text v4 reports for the duplicate pseudo-IRR object.
pub fn duplicate_error(roa: &Roa) -> RoaImportError {
    RoaImportError::Other(messages::pseudo_irr_unique_violation(
        &roa.pseudo_pk(),
        RPKI_IRR_PSEUDO_SOURCE,
        roa.pseudo_class(),
    ))
}

fn slurm_record_repr(d: &RawRoa) -> String {
    let mut parts = Vec::new();
    for (k, v) in [
        ("asn", &d.asn),
        ("prefix", &d.prefix),
        ("maxLength", &d.max_length),
        ("ta", &d.ta),
    ] {
        if let Some(v) = v {
            parts.push(format!(
                "{}: {}",
                rpsl::python::repr(k),
                PyValue::from_json(v).repr()
            ));
        }
    }
    format!("{{{}}}", parts.join(", "))
}

/// `repr(roa_dict)` of entry `idx` of the `roas` list, keys in file order.
fn record_repr(text: &str, idx: usize) -> String {
    #[derive(Deserialize)]
    struct Doc {
        roas: Vec<PyValue>,
    }
    serde_json::from_str::<Doc>(text)
        .ok()
        .and_then(|d| d.roas.into_iter().nth(idx))
        .map(|v| v.repr())
        .unwrap_or_default()
}

/// A JSON value as Python holds it after `ujson.loads`: dicts keep key
/// order, so `repr()` matches v4's.
#[derive(Debug, Clone, PartialEq)]
enum PyValue {
    None,
    Bool(bool),
    Int(String),
    Float(f64),
    Str(String),
    List(Vec<PyValue>),
    Dict(Vec<(String, PyValue)>),
}

impl PyValue {
    fn from_json(v: &serde_json::Value) -> PyValue {
        match v {
            serde_json::Value::Null => PyValue::None,
            serde_json::Value::Bool(b) => PyValue::Bool(*b),
            serde_json::Value::Number(n) if n.is_f64() => {
                PyValue::Float(n.as_f64().unwrap_or_default())
            }
            serde_json::Value::Number(n) => PyValue::Int(n.to_string()),
            serde_json::Value::String(s) => PyValue::Str(s.clone()),
            serde_json::Value::Array(a) => {
                PyValue::List(a.iter().map(PyValue::from_json).collect())
            }
            serde_json::Value::Object(o) => PyValue::Dict(
                o.iter()
                    .map(|(k, v)| (k.clone(), PyValue::from_json(v)))
                    .collect(),
            ),
        }
    }

    fn repr(&self) -> String {
        match self {
            PyValue::None => "None".into(),
            PyValue::Bool(true) => "True".into(),
            PyValue::Bool(false) => "False".into(),
            PyValue::Int(i) => i.clone(),
            PyValue::Float(f) => {
                if f.fract() == 0.0 && f.abs() < 1e16 {
                    format!("{f:.1}")
                } else {
                    format!("{f}")
                }
            }
            PyValue::Str(s) => rpsl::python::repr(s),
            PyValue::List(l) => format!(
                "[{}]",
                l.iter().map(PyValue::repr).collect::<Vec<_>>().join(", ")
            ),
            PyValue::Dict(d) => format!(
                "{{{}}}",
                d.iter()
                    .map(|(k, v)| format!("{}: {}", rpsl::python::repr(k), v.repr()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

impl<'de> Deserialize<'de> for PyValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = PyValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_unit<E: de::Error>(self) -> Result<PyValue, E> {
                Ok(PyValue::None)
            }
            fn visit_bool<E: de::Error>(self, b: bool) -> Result<PyValue, E> {
                Ok(PyValue::Bool(b))
            }
            fn visit_i64<E: de::Error>(self, i: i64) -> Result<PyValue, E> {
                Ok(PyValue::Int(i.to_string()))
            }
            fn visit_u64<E: de::Error>(self, i: u64) -> Result<PyValue, E> {
                Ok(PyValue::Int(i.to_string()))
            }
            fn visit_f64<E: de::Error>(self, f: f64) -> Result<PyValue, E> {
                Ok(PyValue::Float(f))
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<PyValue, E> {
                Ok(PyValue::Str(s.to_owned()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<PyValue, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = a.next_element()? {
                    out.push(v);
                }
                Ok(PyValue::List(out))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<PyValue, A::Error> {
                let mut out: Vec<(String, PyValue)> = Vec::new();
                while let Some((k, v)) = a.next_entry::<String, PyValue>()? {
                    // A repeated key keeps its first position, last value.
                    if let Some(slot) = out.iter_mut().find(|(x, _)| *x == k) {
                        slot.1 = v;
                    } else {
                        out.push((k, v));
                    }
                }
                Ok(PyValue::Dict(out))
            }
        }
        d.deserialize_any(V)
    }
}

#[cfg(test)]
mod tests {
    //! v4's `irrd/rpki/tests/test_importer.py`.

    use super::*;
    use crate::ScopeFilterConfig;

    const REMARKS: &str = "This AS{asn} route object represents routing data retrieved\nfrom the RPKI. This route object is the result of an automated\nRPKI-to-IRR conversion process performed by IRRd.\n";

    fn err(json: &str, slurm: Option<&str>) -> String {
        RoaImport::parse(json, slurm)
            .expect_err("should fail")
            .to_string()
    }

    #[test]
    fn valid_process() {
        let rpki = r#"{"roas": [
            {"asn": "64496", "prefix": "192.0.2.0/24", "maxLength": 26, "ta": "APNIC RPKI Root"},
            {"asn": "AS64497", "prefix": "2001:db8::/32", "maxLength": 40, "ta": "RIPE NCC RPKI Root"},
            {"asn": "64498", "prefix": "192.0.2.0/24", "maxLength": 32, "ta": "APNIC RPKI Root"},
            {"asn": "AS64496", "prefix": "203.0.113.0/25", "maxLength": 26, "ta": "APNIC RPKI Root"},
            {"asn": "AS64497", "prefix": "203.0.113.0/26", "maxLength": 26, "ta": "APNIC RPKI Root"},
            {"asn": "AS64497", "prefix": "203.0.113.128/26", "maxLength": 26, "ta": "APNIC RPKI Root"}
        ]}"#;
        let slurm = r#"{"slurmVersion": 1,
            "validationOutputFilters": {"prefixFilters": [
                {"prefix": "203.0.113.0/25"},
                {"asn": 64498},
                {"prefix": "203.0.113.128/25", "asn": 64497},
                {"prefix": "192.0.2.0/24", "asn": 64497},
                {"prefix": "198.51.100.0/24", "asn": 64496}
            ]},
            "locallyAddedAssertions": {"prefixAssertions": [
                {"asn": 64496, "prefix": "198.51.100.0/24"},
                {"asn": 64497, "prefix": "2001:DB8::/32", "maxPrefixLength": 48}
            ]}}"#;
        let imp = RoaImport::parse(rpki, Some(slurm)).expect("parsed");
        let got: Vec<(String, u32, i64, &str)> = imp
            .roas
            .iter()
            .map(|r| {
                (
                    r.prefix_str.clone(),
                    r.asn,
                    r.max_length,
                    r.trust_anchor.as_str(),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("192.0.2.0/24".to_owned(), 64496, 26, "APNIC RPKI Root"),
                ("2001:db8::/32".to_owned(), 64497, 40, "RIPE NCC RPKI Root"),
                ("198.51.100.0/24".to_owned(), 64496, 24, "SLURM file"),
                ("2001:db8::/32".to_owned(), 64497, 48, "SLURM file"),
            ]
        );
        assert_eq!(imp.roas[0].pseudo_pk(), "192.0.2.0/24AS64496/ML26");
        assert_eq!(imp.roas[1].pseudo_class(), "route6");
        let sf = ScopeFilterValidator::new(ScopeFilterConfig::default());
        let obj = imp.roas[0].pseudo_object(REMARKS, &sf).expect("object");
        assert_eq!(
            obj.parsed_data,
            Json::canonical(
                r#"{"route": "192.0.2.0/24", "origin": "AS64496", "source": "RPKI", "rpki_max_length": 26}"#
            )
            .expect("json")
        );
        assert_eq!(
            obj.object_text,
            "route:          192.0.2.0/24\n\
             descr:          RPKI ROA for 192.0.2.0/24 / AS64496\n\
             remarks:        This AS64496 route object represents routing data retrieved\n\
             \x20               from the RPKI. This route object is the result of an automated\n\
             \x20               RPKI-to-IRR conversion process performed by IRRd.\n\
             max-length:     26\n\
             origin:         AS64496\n\
             source:         RPKI  # Trust Anchor: APNIC RPKI Root\n"
        );
        assert_eq!(obj.rpki_status, RpkiStatus::Valid);
        assert_eq!(imp.first_duplicate(), None);
    }

    #[test]
    fn invalid_json() {
        assert_eq!(
            err("invalid", None),
            "Unable to parse ROA input: invalid JSON: Expected object or value"
        );
        assert_eq!(
            err(r#"{"invalid root": 42}"#, None),
            "Unable to parse ROA input: root key \"roas\" not found"
        );
    }

    #[test]
    fn invalid_data_in_roa() {
        assert_eq!(
            err(
                r#"{"roas": [{"asn": "AS64496", "prefix": "192.0.2.999/24", "maxLength": 26, "ta": "APNIC RPKI Root"}]}"#,
                None
            ),
            "Invalid value in ROA or SLURM: '192.0.2.999': single byte must be 0 <= byte < 256"
        );
        assert_eq!(
            err(
                r#"{"roas": [{"asn": "ASx", "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "APNIC RPKI Root"}]}"#,
                None
            ),
            "Invalid value in ROA or SLURM: Invalid AS number ASX: number part is not numeric"
        );
        assert_eq!(
            err(
                r#"{"roas": [{"prefix": "192.0.2.0/24", "maxLength": 24, "ta": "APNIC RPKI Root"}]}"#,
                None
            ),
            "Unable to parse ROA record: missing key 'asn' -- full record: {'prefix': '192.0.2.0/24', 'maxLength': 24, 'ta': 'APNIC RPKI Root'}"
        );
        assert_eq!(
            err(
                r#"{"roas": [{"asn": "AS64496", "prefix": "192.0.2.0/24", "maxLength": 22, "ta": "APNIC RPKI Root"}]}"#,
                None
            ),
            "Invalid ROA: prefix size 24 is smaller than max length 22 in ROA for 192.0.2.0/24 / AS64496"
        );
        assert_eq!(
            err(
                r#"{"roas": [{"asn": "AS64496", "prefix": "192.0.2.0/24", "maxLength": "xx", "ta": "APNIC RPKI Root"}]}"#,
                None
            ),
            "Invalid value in ROA: invalid literal for int() with base 10: 'xx'"
        );
    }

    #[test]
    fn invalid_slurm_version() {
        assert_eq!(
            err(r#"{"roas": []}"#, Some(r#"{"slurmVersion": 2}"#)),
            "SLURM data has invalid version: 2"
        );
    }

    #[test]
    fn duplicate_across_trust_anchors() {
        let imp = RoaImport::parse(
            r#"{"roas": [
                {"asn": "AS1", "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "a"},
                {"asn": "AS2", "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "a"},
                {"asn": "AS1", "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "b"}
            ]}"#,
            None,
        )
        .expect("parsed");
        let d = imp.first_duplicate().expect("duplicate");
        assert_eq!(d.trust_anchor, "b");
        assert_eq!(
            duplicate_error(d).to_string(),
            "(psycopg2.errors.UniqueViolation) duplicate key value violates unique constraint \"rpsl_objects_rpsl_pk_source_class_unique\"\nDETAIL:  Key (rpsl_pk, source, object_class)=(192.0.2.0/24AS1/ML24, RPKI, route) already exists.\n"
        );
    }

    #[test]
    fn host_prefix_and_remarks_format() {
        let imp = RoaImport::parse(
            r#"{"roas": [{"asn": 65000, "prefix": "192.0.2.1/32", "maxLength": "32", "ta": "x"}]}"#,
            None,
        )
        .expect("parsed");
        assert_eq!(imp.roas[0].pseudo_pk(), "192.0.2.1AS65000/ML32");
        assert_eq!(
            imp.roas[0].pseudo_text("{prefix} {{x}}").expect("text"),
            "route:          192.0.2.1\ndescr:          RPKI ROA for 192.0.2.1 / AS65000\nremarks:        192.0.2.1 {x}\nmax-length:     32\norigin:         AS65000\nsource:         RPKI  # Trust Anchor: x\n"
        );
        assert_eq!(
            imp.roas[0]
                .pseudo_text("{other}")
                .expect_err("key error")
                .to_string(),
            "'other'"
        );
    }

    #[test]
    fn slurm_prefix_filters_cover_unions() {
        let imp = RoaImport::parse(
            r#"{"roas": [{"asn": "AS1", "prefix": "10.0.0.0/24", "maxLength": 24, "ta": "a"},
                         {"asn": "AS1", "prefix": "10.0.1.0/24", "maxLength": 24, "ta": "a"}]}"#,
            Some(
                r#"{"slurmVersion": 1, "validationOutputFilters": {"prefixFilters": [
                    {"prefix": "10.0.0.0/25"}, {"prefix": "10.0.0.128/25"}]}}"#,
            ),
        )
        .expect("parsed");
        assert_eq!(imp.roas.len(), 1);
        assert_eq!(imp.roas[0].prefix_str, "10.0.1.0/24");
    }
}
