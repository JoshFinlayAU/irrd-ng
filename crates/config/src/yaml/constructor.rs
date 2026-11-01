//! `yaml/constructor.py`, `SafeConstructor` only.
//!
//! PyYAML builds collections through generators that it runs breadth first
//! after the root object exists, so when a document has several construction
//! errors the one reported is the first in that order, not in document
//! order. `construct_document` first replays that schedule to find the error
//! PyYAML would raise, then builds the value tree.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use num_bigint::BigInt;
use regex::Regex;

use super::composer::{Node, NodeId, NodeValue};
use super::{Error, MarkedError};
use crate::python::{DateTime, Dict, PyException, Value, float_from_str, int_from_str, str_repr};

type Result<T> = std::result::Result<T, Error>;

const TAG_NULL: &str = "tag:yaml.org,2002:null";
const TAG_BOOL: &str = "tag:yaml.org,2002:bool";
const TAG_INT: &str = "tag:yaml.org,2002:int";
const TAG_FLOAT: &str = "tag:yaml.org,2002:float";
const TAG_BINARY: &str = "tag:yaml.org,2002:binary";
const TAG_TIMESTAMP: &str = "tag:yaml.org,2002:timestamp";
const TAG_OMAP: &str = "tag:yaml.org,2002:omap";
const TAG_PAIRS: &str = "tag:yaml.org,2002:pairs";
const TAG_SET: &str = "tag:yaml.org,2002:set";
const TAG_STR: &str = "tag:yaml.org,2002:str";
const TAG_SEQ: &str = "tag:yaml.org,2002:seq";
const TAG_MAP: &str = "tag:yaml.org,2002:map";
const TAG_MERGE: &str = "tag:yaml.org,2002:merge";
const TAG_VALUE: &str = "tag:yaml.org,2002:value";

/// Python's default recursion limit, for runaway merges and cycles.
const RECURSION_LIMIT: usize = 1000;

/// The most values one document may build. PyYAML shares the object an
/// alias points to, so a few lines of nested aliases cost it nothing;
/// irrd-ng copies them, and without a bound such a file would exhaust
/// memory. A real `irrd.yaml` builds a few hundred.
pub(crate) const MAX_VALUES: usize = 1_000_000;

fn constructor_error(
    context: Option<&str>,
    context_mark: Option<super::Mark>,
    problem: String,
    problem_mark: super::Mark,
) -> Error {
    Error::Marked(MarkedError::new(
        context,
        context_mark,
        problem,
        Some(problem_mark),
    ))
}

fn recursion_error() -> Error {
    Error::Crash(PyException::new(
        "RecursionError",
        "maximum recursion depth exceeded",
    ))
}

fn is_generator_tag(tag: &str) -> bool {
    matches!(tag, TAG_OMAP | TAG_PAIRS | TAG_SET | TAG_SEQ | TAG_MAP)
}

fn is_scalar_tag(tag: &str) -> bool {
    matches!(
        tag,
        TAG_NULL | TAG_BOOL | TAG_INT | TAG_FLOAT | TAG_BINARY | TAG_TIMESTAMP | TAG_STR
    )
}

struct Constructor<'a> {
    nodes: &'a mut Vec<Node>,
    constructed: HashSet<NodeId>,
    scalars: HashMap<NodeId, Value>,
    state_generators: Vec<NodeId>,
    built: std::cell::Cell<usize>,
}

/// `construct_document(node)`.
pub(crate) fn construct_document(nodes: &mut Vec<Node>, root: NodeId) -> Result<Value> {
    let mut c = Constructor {
        nodes,
        constructed: HashSet::new(),
        scalars: HashMap::new(),
        state_generators: Vec::new(),
        built: std::cell::Cell::new(0),
    };
    c.construct_object(root)?;
    while !c.state_generators.is_empty() {
        let generators = std::mem::take(&mut c.state_generators);
        for g in generators {
            c.run_generator(g)?;
        }
    }
    let mut stack = Vec::new();
    c.build(root, &mut stack)
}

impl Constructor<'_> {
    fn construct_object(&mut self, id: NodeId) -> Result<()> {
        if self.constructed.contains(&id) {
            return Ok(());
        }
        let tag = self.nodes[id].tag.clone();
        if is_generator_tag(&tag) {
            self.constructed.insert(id);
            self.state_generators.push(id);
            return Ok(());
        }
        if is_scalar_tag(&tag) {
            let value = self.construct_scalar_value(id, &tag)?;
            self.scalars.insert(id, value);
            self.constructed.insert(id);
            return Ok(());
        }
        Err(constructor_error(
            None,
            None,
            format!(
                "could not determine a constructor for the tag {}",
                str_repr(&tag)
            ),
            self.nodes[id].start_mark,
        ))
    }

    /// `SafeConstructor.construct_scalar`.
    fn construct_scalar(&self, id: NodeId) -> Result<String> {
        self.construct_scalar_depth(id, 0)
    }

    fn construct_scalar_depth(&self, id: NodeId, depth: usize) -> Result<String> {
        if depth > RECURSION_LIMIT {
            return Err(recursion_error());
        }
        let node = &self.nodes[id];
        match &node.value {
            NodeValue::Scalar(s) => Ok(s.clone()),
            NodeValue::Mapping(items) => {
                for (k, v) in items {
                    if self.nodes[*k].tag == TAG_VALUE {
                        return self.construct_scalar_depth(*v, depth + 1);
                    }
                }
                Err(constructor_error(
                    None,
                    None,
                    format!("expected a scalar node, but found {}", node.id()),
                    node.start_mark,
                ))
            }
            NodeValue::Sequence(_) => Err(constructor_error(
                None,
                None,
                format!("expected a scalar node, but found {}", node.id()),
                node.start_mark,
            )),
        }
    }

    fn construct_scalar_value(&self, id: NodeId, tag: &str) -> Result<Value> {
        let value = self.construct_scalar(id)?;
        match tag {
            TAG_NULL => Ok(Value::None),
            TAG_STR => Ok(Value::Str(value)),
            TAG_BOOL => match value.to_lowercase().as_str() {
                "yes" | "true" | "on" => Ok(Value::Bool(true)),
                "no" | "false" | "off" => Ok(Value::Bool(false)),
                other => Err(Error::Crash(PyException::new("KeyError", str_repr(other)))),
            },
            TAG_INT => construct_yaml_int(&value).map(Value::Int),
            TAG_FLOAT => construct_yaml_float(&value).map(Value::Float),
            TAG_BINARY => construct_yaml_binary(&value)
                .map(Value::Bytes)
                .map_err(|problem| {
                    constructor_error(None, None, problem, self.nodes[id].start_mark)
                }),
            TAG_TIMESTAMP => {
                // PyYAML matches against node.value, not the constructed scalar.
                let raw = match &self.nodes[id].value {
                    NodeValue::Scalar(s) => s.clone(),
                    _ => value,
                };
                construct_yaml_timestamp(&raw)
            }
            _ => Ok(Value::None),
        }
    }

    fn run_generator(&mut self, id: NodeId) -> Result<()> {
        let tag = self.nodes[id].tag.clone();
        match tag.as_str() {
            TAG_SEQ => {
                let children = match &self.nodes[id].value {
                    NodeValue::Sequence(items) => items.clone(),
                    _ => {
                        let node = &self.nodes[id];
                        return Err(constructor_error(
                            None,
                            None,
                            format!("expected a sequence node, but found {}", node.id()),
                            node.start_mark,
                        ));
                    }
                };
                for child in children {
                    self.construct_object(child)?;
                }
                Ok(())
            }
            TAG_MAP | TAG_SET => self.construct_mapping(id),
            TAG_OMAP | TAG_PAIRS => {
                let context = if tag == TAG_OMAP {
                    "while constructing an ordered map"
                } else {
                    "while constructing pairs"
                };
                let node_mark = self.nodes[id].start_mark;
                let children = match &self.nodes[id].value {
                    NodeValue::Sequence(items) => items.clone(),
                    _ => {
                        return Err(constructor_error(
                            Some(context),
                            Some(node_mark),
                            format!("expected a sequence, but found {}", self.nodes[id].id()),
                            node_mark,
                        ));
                    }
                };
                for sub in children {
                    let subnode = &self.nodes[sub];
                    let NodeValue::Mapping(items) = &subnode.value else {
                        return Err(constructor_error(
                            Some(context),
                            Some(node_mark),
                            format!("expected a mapping of length 1, but found {}", subnode.id()),
                            subnode.start_mark,
                        ));
                    };
                    if items.len() != 1 {
                        return Err(constructor_error(
                            Some(context),
                            Some(node_mark),
                            format!(
                                "expected a single mapping item, but found {} items",
                                items.len()
                            ),
                            subnode.start_mark,
                        ));
                    }
                    let (k, v) = items[0];
                    self.construct_object(k)?;
                    self.construct_object(v)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn construct_mapping(&mut self, id: NodeId) -> Result<()> {
        if matches!(self.nodes[id].value, NodeValue::Mapping(_)) {
            self.flatten_mapping(id, 0)?;
        }
        let node = &self.nodes[id];
        let NodeValue::Mapping(items) = &node.value else {
            return Err(constructor_error(
                None,
                None,
                format!("expected a mapping node, but found {}", node.id()),
                node.start_mark,
            ));
        };
        let node_mark = node.start_mark;
        let items = items.clone();
        for (k, v) in items {
            self.construct_object(k)?;
            if is_generator_tag(&self.nodes[k].tag) {
                return Err(constructor_error(
                    Some("while constructing a mapping"),
                    Some(node_mark),
                    "found unhashable key".to_owned(),
                    self.nodes[k].start_mark,
                ));
            }
            self.construct_object(v)?;
        }
        Ok(())
    }

    fn flatten_mapping(&mut self, id: NodeId, depth: usize) -> Result<()> {
        if depth > RECURSION_LIMIT {
            return Err(recursion_error());
        }
        let node_mark = self.nodes[id].start_mark;
        let mut merge: Vec<(NodeId, NodeId)> = Vec::new();
        let mut index = 0;
        while let NodeValue::Mapping(items) = &self.nodes[id].value
            && index < items.len()
        {
            let (key_node, value_node) = items[index];
            let key_tag = self.nodes[key_node].tag.clone();
            if key_tag == TAG_MERGE {
                if let NodeValue::Mapping(items) = &mut self.nodes[id].value {
                    items.remove(index);
                }
                match self.nodes[value_node].value.clone() {
                    NodeValue::Mapping(_) => {
                        self.flatten_mapping(value_node, depth + 1)?;
                        if let NodeValue::Mapping(sub) = &self.nodes[value_node].value {
                            merge.extend(sub.iter().copied());
                        }
                    }
                    NodeValue::Sequence(subnodes) => {
                        let mut submerge = Vec::new();
                        for sub in subnodes {
                            if !matches!(self.nodes[sub].value, NodeValue::Mapping(_)) {
                                return Err(constructor_error(
                                    Some("while constructing a mapping"),
                                    Some(node_mark),
                                    format!(
                                        "expected a mapping for merging, but found {}",
                                        self.nodes[sub].id()
                                    ),
                                    self.nodes[sub].start_mark,
                                ));
                            }
                            self.flatten_mapping(sub, depth + 1)?;
                            if let NodeValue::Mapping(items) = &self.nodes[sub].value {
                                submerge.push(items.clone());
                            }
                        }
                        for value in submerge.into_iter().rev() {
                            merge.extend(value);
                        }
                    }
                    NodeValue::Scalar(_) => {
                        return Err(constructor_error(
                            Some("while constructing a mapping"),
                            Some(node_mark),
                            format!(
                                "expected a mapping or list of mappings for merging, but found {}",
                                self.nodes[value_node].id()
                            ),
                            self.nodes[value_node].start_mark,
                        ));
                    }
                }
            } else if key_tag == TAG_VALUE {
                self.nodes[key_node].tag = TAG_STR.to_owned();
                index += 1;
            } else {
                index += 1;
            }
        }
        if !merge.is_empty()
            && let NodeValue::Mapping(items) = &mut self.nodes[id].value
        {
            merge.append(items);
            *items = merge;
        }
        Ok(())
    }

    /// Build the Python object for a node whose construction succeeded.
    fn build(&self, id: NodeId, stack: &mut Vec<NodeId>) -> Result<Value> {
        self.built.set(self.built.get() + 1);
        if self.built.get() > MAX_VALUES {
            return Err(Error::Crash(PyException::new(
                "MemoryError",
                format!("YAML aliases expand to more than {MAX_VALUES} values"),
            )));
        }
        if let Some(v) = self.scalars.get(&id) {
            return Ok(v.clone());
        }
        if stack.contains(&id) {
            // A collection containing itself. Python builds it; v4 only
            // trips over it if it is inside the `irrd` mapping.
            return Ok(Value::Recursive {
                mapping: matches!(self.nodes[id].value, NodeValue::Mapping(_)),
            });
        }
        if stack.len() > RECURSION_LIMIT {
            return Err(recursion_error());
        }
        stack.push(id);
        let node = &self.nodes[id];
        let result = match (node.tag.as_str(), &node.value) {
            (TAG_SEQ, NodeValue::Sequence(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(self.build(*item, stack)?);
                }
                Value::List(out)
            }
            (TAG_MAP, NodeValue::Mapping(items)) => {
                let mut dict = Dict::new();
                for (k, v) in items {
                    let key = self.build(*k, stack)?;
                    let value = self.build(*v, stack)?;
                    dict.insert(key, value);
                }
                Value::Dict(dict)
            }
            (TAG_SET, NodeValue::Mapping(items)) => {
                let mut dict = Dict::new();
                for (k, v) in items {
                    let key = self.build(*k, stack)?;
                    let value = self.build(*v, stack)?;
                    dict.insert(key, value);
                }
                Value::Set(dict.keys().cloned().collect())
            }
            (TAG_OMAP | TAG_PAIRS, NodeValue::Sequence(items)) => {
                let mut out = Vec::new();
                for sub in items {
                    if let NodeValue::Mapping(pairs) = &self.nodes[*sub].value
                        && let Some((k, v)) = pairs.first()
                    {
                        out.push(Value::Tuple(vec![
                            self.build(*k, stack)?,
                            self.build(*v, stack)?,
                        ]));
                    }
                }
                Value::List(out)
            }
            _ => Value::None,
        };
        stack.pop();
        Ok(result)
    }
}

/// `SafeConstructor.construct_yaml_int`.
fn construct_yaml_int(raw: &str) -> Result<BigInt> {
    let value = raw.replace('_', "");
    let Some(first) = value.chars().next() else {
        return Err(Error::Crash(PyException::new(
            "IndexError",
            "string index out of range",
        )));
    };
    let negative = first == '-';
    let mut value = value.as_str();
    if first == '-' || first == '+' {
        value = &value[1..];
    }
    let magnitude = if value == "0" {
        BigInt::from(0)
    } else if let Some(rest) = value.strip_prefix("0b") {
        int_from_str(rest, 2)?
    } else if let Some(rest) = value.strip_prefix("0x") {
        int_from_str(rest, 16)?
    } else if value.starts_with('0') {
        int_from_str(value, 8)?
    } else if value.contains(':') {
        let mut digits = Vec::new();
        for part in value.split(':') {
            digits.push(int_from_str(part, 10)?);
        }
        let mut total = BigInt::from(0);
        let mut base = BigInt::from(1);
        for d in digits.iter().rev() {
            total += d * &base;
            base *= 60;
        }
        total
    } else {
        int_from_str(value, 10)?
    };
    Ok(if negative { -magnitude } else { magnitude })
}

/// `SafeConstructor.construct_yaml_float`.
fn construct_yaml_float(raw: &str) -> Result<f64> {
    let value = raw.replace('_', "").to_lowercase();
    let Some(first) = value.chars().next() else {
        return Err(Error::Crash(PyException::new(
            "IndexError",
            "string index out of range",
        )));
    };
    let sign = if first == '-' { -1.0 } else { 1.0 };
    let mut value = value.as_str();
    if first == '-' || first == '+' {
        value = &value[1..];
    }
    if value == ".inf" {
        return Ok(sign * f64::INFINITY);
    }
    if value == ".nan" {
        return Ok(f64::NAN);
    }
    if value.contains(':') {
        let mut digits = Vec::new();
        for part in value.split(':') {
            digits.push(float_from_str(part)?);
        }
        let mut total = 0.0;
        let mut base = 1.0;
        for d in digits.iter().rev() {
            total += d * base;
            base *= 60.0;
        }
        return Ok(sign * total);
    }
    Ok(sign * float_from_str(value)?)
}

/// `base64.decodebytes`, returning the `ConstructorError` problem text.
fn construct_yaml_binary(raw: &str) -> std::result::Result<Vec<u8>, String> {
    if let Some(bad) = raw.chars().find(|c| !c.is_ascii()) {
        let pos = raw.chars().position(|c| c == bad).unwrap_or(0);
        return Err(format!(
            "failed to convert base64 data into ascii: 'ascii' codec can't encode character {} in position {pos}: ordinal not in range(128)",
            str_repr(&bad.to_string())
        ));
    }
    let decode = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    let mut quad = 0usize;
    let mut data_chars = 0usize;
    let mut pads = 0usize;
    for b in raw.bytes() {
        if b == b'=' {
            if quad >= 2 {
                pads += 1;
                if quad + pads >= 4 {
                    return Ok(out);
                }
            }
            continue;
        }
        let Some(v) = decode(b) else { continue };
        if pads > 0 {
            // Data after padding: binascii restarts accumulating.
            pads = 0;
        }
        data_chars += 1;
        acc = (acc << 6) | v;
        bits += 6;
        quad = (quad + 1) % 4;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
        }
    }
    if quad == 1 {
        return Err(format!(
            "failed to decode base64 data: Invalid base64-encoded string: number of data characters ({data_chars}) cannot be 1 more than a multiple of 4"
        ));
    }
    if quad != 0 {
        return Err("failed to decode base64 data: Incorrect padding".to_owned());
    }
    Ok(out)
}

static TIMESTAMP: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(
        r"\A(?P<year>[0-9][0-9][0-9][0-9])-(?P<month>[0-9][0-9]?)-(?P<day>[0-9][0-9]?)(?:(?:[Tt]|[ \t]+)(?P<hour>[0-9][0-9]?):(?P<minute>[0-9][0-9]):(?P<second>[0-9][0-9])(?:\.(?P<fraction>[0-9]*))?(?:[ \t]*(?P<tz>Z|(?P<tz_sign>[-+])(?P<tz_hour>[0-9][0-9]?)(?::(?P<tz_minute>[0-9][0-9]))?))?)?\n?\z",
    )
    .expect("static timestamp pattern")
});

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

/// `SafeConstructor.construct_yaml_timestamp`.
fn construct_yaml_timestamp(raw: &str) -> Result<Value> {
    let Some(caps) = TIMESTAMP.captures(raw) else {
        return Err(Error::Crash(PyException::new(
            "AttributeError",
            "'NoneType' object has no attribute 'groupdict'",
        )));
    };
    let num = |name: &str| -> u32 {
        caps.name(name)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0)
    };
    let year = i32::try_from(num("year")).unwrap_or(0);
    let month = num("month");
    let day = num("day");
    let check_date = || -> Result<()> {
        if !(1..=9999).contains(&year) {
            return Err(Error::Crash(PyException::value_error(format!(
                "year {year} is out of range"
            ))));
        }
        if !(1..=12).contains(&month) {
            return Err(Error::Crash(PyException::value_error(
                "month must be in 1..12",
            )));
        }
        if day < 1 || day > days_in_month(year, month) {
            return Err(Error::Crash(PyException::value_error(format!(
                "day {day} must be in range 1..{} for month {month} in year {year}",
                days_in_month(year, month)
            ))));
        }
        Ok(())
    };
    if caps.name("hour").is_none_or(|m| m.as_str().is_empty()) {
        check_date()?;
        return Ok(Value::Date { year, month, day });
    }
    let hour = num("hour");
    let minute = num("minute");
    let second = num("second");
    let mut microsecond = 0;
    if let Some(f) = caps.name("fraction").map(|m| m.as_str())
        && !f.is_empty()
    {
        let mut frac: String = f.chars().take(6).collect();
        while frac.len() < 6 {
            frac.push('0');
        }
        microsecond = frac.parse().unwrap_or(0);
    }
    let mut utc_offset = None;
    if let Some(sign) = caps.name("tz_sign") {
        let offset = i32::try_from(num("tz_hour") * 3600 + num("tz_minute") * 60).unwrap_or(0);
        let offset = if sign.as_str() == "-" {
            -offset
        } else {
            offset
        };
        if offset.abs() >= 86400 {
            return Err(Error::Crash(PyException::value_error(
                "offset must be a timedelta strictly between -timedelta(hours=24) and timedelta(hours=24).",
            )));
        }
        utc_offset = Some(offset);
    } else if caps.name("tz").is_some() {
        utc_offset = Some(0);
    }
    check_date()?;
    for (value, name, max) in [
        (hour, "hour", 23),
        (minute, "minute", 59),
        (second, "second", 59),
    ] {
        if value > max {
            return Err(Error::Crash(PyException::value_error(format!(
                "{name} must be in 0..{max}"
            ))));
        }
    }
    Ok(Value::DateTime(DateTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        microsecond,
        utc_offset,
    }))
}
