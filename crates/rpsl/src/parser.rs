//! `RPSLObject` (`irrd/rpsl/parser.py`) and `rpsl_object_from_text`
//! (`irrd/rpsl/rpsl_objects.py`).

use std::fmt;

use crate::classes::{self, ClassDef};
use crate::fields::{FieldParseResult, PASSWORD_HASH_DUMMY_VALUE, ParseCtx, Uncaught};
use crate::ipy::Ip;
use crate::messages;
use crate::parser_state::Messages;
use crate::pgp::Keyring;
use crate::py;
use crate::settings::RpslSettings;
use crate::text::splitline_unicodesafe;
use crate::validators::parse_as_number;

/// `RPSL_ATTRIBUTE_TEXT_WIDTH`.
pub const RPSL_ATTRIBUTE_TEXT_WIDTH: usize = 16;

/// A parsed attribute value in `parsed_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A single value (attributes that may occur once).
    Str(String),
    /// A list of values (attributes that may occur more than once, and
    /// comma separated lists).
    List(Vec<String>),
}

impl Value {
    /// Python truthiness: false for an empty string or list.
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Str(s) => !s.is_empty(),
            Value::List(l) => !l.is_empty(),
        }
    }

    /// The single value, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            Value::List(_) => None,
        }
    }

    /// The list, if this is one.
    pub fn as_list(&self) -> Option<&[String]> {
        match self {
            Value::Str(_) => None,
            Value::List(l) => Some(l),
        }
    }
}

/// One attribute as it appeared in the object text (`_object_data`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectAttr {
    /// Lower-cased attribute name.
    pub name: String,
    /// Value, continuation lines joined with `\n`, whitespace after the
    /// continuation character removed.
    pub value: String,
    /// The continuation character (` `, `+` or tab) of each continuation
    /// line, needed to render the original text.
    pub continuation_chars: Vec<char>,
}

/// Why no object could be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// `UnknownRPSLObjectClassException`: the first attribute is not one of
    /// the 19 classes. Matching is case-sensitive, as in v4.
    #[error("{}", messages::unknown_object_class(class))]
    UnknownClass {
        /// The class as found in the text.
        class: String,
    },
    /// An exception v4 does not catch while parsing (for example two
    /// `route:` attributes in non-strict mode). v4's import aborts on these;
    /// the text is the exception message v4 would raise.
    #[error("{0}")]
    Uncaught(String),
}

impl From<Uncaught> for ParseError {
    fn from(u: Uncaught) -> Self {
        ParseError::Uncaught(u.0)
    }
}

/// Options for one parse.
#[derive(Debug, Clone, Copy)]
pub struct ParseOptions<'a> {
    /// Strict validation: every attribute is validated, attribute counts are
    /// checked, and class specific `clean()` runs. Non-strict validation only
    /// checks primary and look-up keys and `source`.
    pub strict: bool,
    /// With non-strict validation, accept objects without `source` and use
    /// this one.
    pub default_source: Option<&'a str>,
    /// Settings the parser consults.
    pub settings: &'a RpslSettings,
    /// The PGP keyring key-cert objects are imported into (strict mode).
    pub keyring: &'a Keyring,
}

/// A parsed RPSL object.
#[derive(Debug, Clone)]
pub struct RpslObject {
    class: &'static ClassDef,
    strict: bool,
    default_source: Option<String>,
    messages: Messages,
    object_data: Vec<ObjectAttr>,
    parsed_data: Vec<(&'static str, Value)>,
    /// `ip_first`
    pub ip_first: Option<Ip>,
    /// `ip_last`
    pub ip_last: Option<Ip>,
    /// `prefix`
    pub prefix: Option<Ip>,
    /// `prefix_length`
    pub prefix_length: Option<u32>,
    /// `asn_first`
    pub asn_first: Option<u32>,
    /// `asn_last`
    pub asn_last: Option<u32>,
    /// `pk_asn_segment`, set by [`RpslObject::clean_for_create`].
    pub pk_asn_segment: Option<String>,
}

/// `rpsl_object_from_text(text, strict_validation, default_source)`.
///
/// `text` should already be stripped, as v4's callers do.
pub fn rpsl_object_from_text(
    text: &str,
    options: &ParseOptions<'_>,
) -> Result<RpslObject, ParseError> {
    let first = text.split_once(':').map_or(text, |(a, _)| a);
    let class_name = py::strip(first);
    let Some(class) = classes::class_by_name(class_name) else {
        return Err(ParseError::UnknownClass {
            class: class_name.to_owned(),
        });
    };
    RpslObject::parse(class, text, options)
}

/// Python's `str.split(":", 1)` on a line that contains a colon.
fn split_attr(line: &str) -> (&str, &str) {
    line.split_once(':').unwrap_or((line, ""))
}

fn is_attr_name(name: &str) -> bool {
    // ^[a-z0-9_-]+$
    let name = name.strip_suffix('\n').unwrap_or(name);
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// `_normalise_rpsl_value`.
pub(crate) fn normalise_rpsl_value(value: &str) -> String {
    if !value.contains('\n') {
        let before_comment = value.split('#').next().unwrap_or("");
        return py::strip(before_comment).to_owned();
    }
    let mut lines: Vec<&str> = Vec::new();
    for line in splitline_unicodesafe(value) {
        let parsed = line
            .split('#')
            .next()
            .unwrap_or("")
            .trim_matches(['\n', '\t', ',', ' ']);
        if !parsed.is_empty() {
            lines.push(parsed);
        }
    }
    lines.join(",")
}

impl RpslObject {
    fn parse(
        class: &'static ClassDef,
        text: &str,
        options: &ParseOptions<'_>,
    ) -> Result<RpslObject, ParseError> {
        let mut obj = RpslObject {
            class,
            strict: options.strict,
            default_source: options
                .default_source
                .map(|s| py::upper(py::strip(s)).into_owned())
                .filter(|s| !s.is_empty()),
            messages: Messages::default(),
            object_data: Vec::new(),
            parsed_data: Vec::new(),
            ip_first: None,
            ip_last: None,
            prefix: None,
            prefix_length: None,
            asn_first: None,
            asn_last: None,
            pk_asn_segment: None,
        };
        if !text.is_empty() {
            obj.extract_attributes_values(text);
            obj.validate_object(options)?;
        }
        Ok(obj)
    }

    /// `_extract_attributes_values`.
    fn extract_attributes_values(&mut self, text: &str) {
        let mut current: Option<ObjectAttr> = None;
        for (line_no, line) in splitline_unicodesafe(py::strip(text)).enumerate() {
            let line_no = line_no + 1;
            if line.is_empty() {
                self.messages
                    .error(messages::empty_line_in_object(line_no, line));
                return;
            }
            let first = line.chars().next().unwrap_or(' ');
            if !matches!(first, ' ' | '+' | '\t') {
                if let Some(attr) = current.take()
                    && !attr.name.is_empty()
                    && !self.class.discarded_fields.contains(&attr.name.as_str())
                {
                    self.object_data.push(attr);
                }
                if !line.contains(':') {
                    self.messages
                        .error(messages::neither_continuation_nor_attribute(line_no, line));
                    return;
                }
                let (name, value) = split_attr(line);
                let name = py::lower(name).into_owned();
                if self.class.field(&name).is_none() && !is_attr_name(&name) {
                    self.messages
                        .error(messages::malformed_attribute_name(line_no, &name));
                    return;
                }
                current = Some(ObjectAttr {
                    name,
                    value: py::strip(value).to_owned(),
                    continuation_chars: Vec::new(),
                });
            } else {
                let rest = py::strip(&line[first.len_utf8()..]);
                let attr = current.get_or_insert_with(|| ObjectAttr {
                    name: String::new(),
                    value: String::new(),
                    continuation_chars: Vec::new(),
                });
                attr.value.push('\n');
                attr.value.push_str(rest);
                attr.continuation_chars.push(first);
            }
        }
        if let Some(attr) = current
            && !attr.name.is_empty()
            && !self.class.discarded_fields.contains(&attr.name.as_str())
        {
            self.object_data.push(attr);
        }
    }

    /// `_validate_object`.
    fn validate_object(&mut self, options: &ParseOptions<'_>) -> Result<(), ParseError> {
        if !self.messages.has_errors() {
            self.validate_attribute_counts();
        }
        let allow_invalid_metadata = self.messages.has_errors();
        self.parse_attribute_data(allow_invalid_metadata, options)?;
        if self.strict && !self.messages.has_errors() {
            self.clean(options)?;
        }
        Ok(())
    }

    /// `_validate_attribute_counts`.
    fn validate_attribute_counts(&mut self) {
        let mut present: Vec<(&str, usize)> = Vec::new();
        for attr in &self.object_data {
            match present.iter_mut().find(|(n, _)| *n == attr.name) {
                Some((_, c)) => *c += 1,
                None => present.push((&attr.name, 1)),
            }
        }
        let class = self.class.name;
        let mut errors: Vec<String> = Vec::new();
        if self.strict {
            for (name, count) in &present {
                if *name == "last-modified" {
                    continue;
                }
                let field = self.class.field(name);
                if field.is_none() {
                    errors.push(messages::unrecognised_attribute(name, class));
                }
                if *count > 1 && !field.is_some_and(|f| f.multiple) {
                    errors.push(messages::attribute_multiple(name, class));
                }
            }
            for field in self.class.fields.iter().filter(|f| !f.optional) {
                if !present.iter().any(|(n, _)| *n == field.name) {
                    errors.push(messages::mandatory_missing(field.name, class));
                }
            }
        } else {
            let mut required: Vec<&str> = self.class.pk_fields().collect();
            if self.default_source.is_none() {
                required.push("source");
            }
            for name in required {
                if !present.iter().any(|(n, _)| *n == name) {
                    errors.push(messages::primary_key_missing(name, class));
                }
            }
        }
        for e in errors {
            self.messages.error(e);
        }
    }

    /// `_parse_attribute_data`.
    fn parse_attribute_data(
        &mut self,
        allow_invalid_metadata: bool,
        options: &ParseOptions<'_>,
    ) -> Result<(), ParseError> {
        let ctx = ParseCtx {
            strict: self.strict,
            settings: options.settings,
        };
        for idx in 0..self.object_data.len() {
            let Some(field) = self.class.field(&self.object_data[idx].name) else {
                continue;
            };
            let value = &self.object_data[idx].value;
            let normalised = normalise_rpsl_value(value);
            let raise_errors =
                self.strict || field.primary_key || field.lookup_key || field.name == "source";
            let parsed = if raise_errors {
                field.parse(&normalised, &mut self.messages, &ctx)?
            } else {
                field.parse(&normalised, &mut Messages::default(), &ctx)?
            };
            let Some(parsed) = parsed else { continue };

            if parsed.value != normalised {
                let new_value = value.replace(&normalised, &parsed.value);
                self.object_data[idx].value = new_value;
            }
            let keep_case = field.kind.keep_case();
            let case = |s: String| {
                if keep_case {
                    s
                } else {
                    py::upper(&s).into_owned()
                }
            };
            match parsed.values_list.as_ref().filter(|l| !l.is_empty()) {
                Some(list) => {
                    let list: Vec<String> = list.iter().cloned().map(case).collect();
                    match self.parsed_value_mut(field.name) {
                        Some(Value::List(existing)) => existing.extend(list),
                        Some(existing @ Value::Str(_)) => {
                            // Python would raise TypeError on str += list;
                            // unreachable as list fields are all multiple.
                            *existing = Value::List(list);
                        }
                        None => self.parsed_data.push((field.name, Value::List(list))),
                    }
                }
                None => {
                    let value_str = case(parsed.value.clone());
                    if field.multiple {
                        match self.parsed_value_mut(field.name) {
                            Some(Value::List(existing)) => existing.push(value_str),
                            Some(existing @ Value::Str(_)) => {
                                *existing = Value::List(vec![value_str]);
                            }
                            None => self
                                .parsed_data
                                .push((field.name, Value::List(vec![value_str]))),
                        }
                    } else {
                        match self.parsed_value_mut(field.name) {
                            // v4 assigns rather than appends here, so a
                            // repeated single attribute becomes "\n" + last.
                            Some(existing) => *existing = Value::Str(format!("\n{value_str}")),
                            None => self.parsed_data.push((field.name, Value::Str(value_str))),
                        }
                    }
                }
            }

            if field.primary_key || field.lookup_key {
                self.extract_metadata(&parsed, allow_invalid_metadata)?;
            }
        }
        if self.parsed_value("source").is_none()
            && let Some(source) = &self.default_source
        {
            self.parsed_data
                .push(("source", Value::Str(source.clone())));
        }
        Ok(())
    }

    fn extract_metadata(
        &mut self,
        parsed: &FieldParseResult,
        allow_invalid: bool,
    ) -> Result<(), ParseError> {
        let value = &parsed.value;
        fn check<T: fmt::Display + Copy>(
            slot: &mut Option<T>,
            new: Option<T>,
            truthy: impl Fn(&T) -> bool,
            name: &str,
            value: &str,
            allow_invalid: bool,
        ) -> Result<(), ParseError> {
            if let Some(n) = new {
                if let Some(existing) = slot.as_ref()
                    && truthy(existing)
                    && !allow_invalid
                {
                    return Err(ParseError::Uncaught(messages::metadata_already_set(
                        value, &n, name, existing,
                    )));
                }
                *slot = Some(n);
            }
            Ok(())
        }
        check(
            &mut self.ip_first,
            parsed.ip_first,
            |_| true,
            "ip_first",
            value,
            allow_invalid,
        )?;
        check(
            &mut self.ip_last,
            parsed.ip_last,
            |_| true,
            "ip_last",
            value,
            allow_invalid,
        )?;
        check(
            &mut self.asn_first,
            parsed.asn_first,
            |v| *v != 0,
            "asn_first",
            value,
            allow_invalid,
        )?;
        check(
            &mut self.asn_last,
            parsed.asn_last,
            |v| *v != 0,
            "asn_last",
            value,
            allow_invalid,
        )?;
        check(
            &mut self.prefix,
            parsed.prefix,
            |_| true,
            "prefix",
            value,
            allow_invalid,
        )?;
        check(
            &mut self.prefix_length,
            parsed.prefix_length,
            |v| *v != 0,
            "prefix_length",
            value,
            allow_invalid,
        )?;
        Ok(())
    }

    /// `clean()`: class specific checks, strict mode only.
    fn clean(&mut self, options: &ParseOptions<'_>) -> Result<(), ParseError> {
        match self.class.name {
            "key-cert" => self.clean_key_cert(options.keyring),
            "mntner" => {
                self.clean_mntner();
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// `RPSLMntner.clean`.
    fn clean_mntner(&mut self) {
        let dummy: Vec<bool> = self
            .auth_hash_lines()
            .map(|(_, hash)| hash == PASSWORD_HASH_DUMMY_VALUE)
            .collect();
        if dummy.iter().any(|&d| d) && !dummy.iter().all(|&d| d) {
            self.messages.error(messages::MNTNER_DUMMY_MIX);
        }
    }

    /// `_auth_lines(password_hashes=True)`: `(scheme, hash)` of every auth
    /// value containing a space.
    fn auth_hash_lines(&self) -> impl Iterator<Item = (&str, &str)> {
        self.parsed_value("auth")
            .and_then(Value::as_list)
            .unwrap_or_default()
            .iter()
            .filter_map(|a| a.split_once(' '))
    }

    /// `RPSLMntner.has_dummy_auth_value`.
    pub fn has_dummy_auth_value(&self) -> bool {
        let mut any = false;
        for (_, hash) in self.auth_hash_lines() {
            any = true;
            if hash != PASSWORD_HASH_DUMMY_VALUE {
                return false;
            }
        }
        any
    }

    /// `RPSLKeyCert.clean`.
    fn clean_key_cert(&mut self, keyring: &Keyring) -> Result<(), ParseError> {
        let certif: Vec<&str> = self
            .parsed_value("certif")
            .and_then(Value::as_list)
            .unwrap_or_default()
            .iter()
            .map(String::as_str)
            .collect();
        let certif_data = certif.join("\n").replace(',', "\n");
        let result = keyring.import_keys(&certif_data)?;

        if result.fingerprints.len() != 1 {
            let mut msg = messages::PGP_KEY_UNREADABLE.to_owned();
            if let Some(first) = result.results.first() {
                msg.push_str(": ");
                msg.push_str(first);
            }
            self.messages.error(msg);
            return Ok(());
        }
        let fingerprint = result.fingerprints[0].clone();
        let tail_start = fingerprint
            .char_indices()
            .rev()
            .nth(7)
            .map_or(0, |(i, _)| i);
        let expected = format!("PGPKEY-{}", &fingerprint[tail_start..]);
        let actual = self
            .parsed_value("key-cert")
            .and_then(Value::as_str)
            .map(|s| py::upper(s).into_owned())
            .unwrap_or_default();
        let formatted = format_fingerprint(&fingerprint);
        if expected != actual {
            self.messages.error(messages::key_cert_name_mismatch(
                &actual, &formatted, &expected,
            ));
            return Ok(());
        }
        let uids = keyring.uids(&fingerprint);
        self.update_attribute_value("fingerpr", vec![formatted], true);
        self.update_attribute_value("owner", uids, true);
        self.update_attribute_value("method", vec!["PGP".to_owned()], true);
        Ok(())
    }

    /// `_update_attribute_value`: replace every occurrence of `attribute`
    /// with `new_values`, inserted from the second line of the object.
    fn update_attribute_value(
        &mut self,
        attribute: &'static str,
        new_values: Vec<String>,
        flatten: bool,
    ) {
        let parsed = if flatten {
            Value::Str(new_values.join("\n"))
        } else {
            Value::List(new_values.clone())
        };
        match self.parsed_value_mut(attribute) {
            Some(existing) => *existing = parsed,
            None => self.parsed_data.push((attribute, parsed)),
        }
        self.object_data.retain(|a| a.name != attribute);
        for (i, value) in new_values.into_iter().enumerate() {
            let at = (1 + i).min(self.object_data.len());
            self.object_data.insert(
                at,
                ObjectAttr {
                    name: attribute.to_owned(),
                    value,
                    continuation_chars: Vec::new(),
                },
            );
        }
    }

    /// `RPSLSet.clean_for_create`: hierarchical set name checks for new
    /// sets. Returns false, with an error recorded, when the first component
    /// of the name must be an AS number and is not. Always true for classes
    /// that are not sets.
    pub fn clean_for_create(&mut self, settings: &RpslSettings) -> bool {
        if !self.class.is_set {
            return true;
        }
        let pk = self.pk();
        let segment = pk.split(':').next().unwrap_or("").to_owned();
        match parse_as_number(&segment, false, false, false) {
            Ok(_) => {
                self.pk_asn_segment = Some(segment);
                true
            }
            Err(e) => {
                self.pk_asn_segment = None;
                let required = |key: &str| settings.set_creation_prefix_required.get(key).copied();
                if required(self.class.name) == Some(false) || required("COMMON") == Some(false) {
                    return true;
                }
                // v4 formats the message after resetting pk_asn_segment.
                self.messages.error(messages::set_name_not_hierarchical(
                    self.class.name,
                    "None",
                    &e,
                ));
                false
            }
        }
    }

    /// The object class name.
    pub fn rpsl_object_class(&self) -> &'static str {
        self.class.name
    }

    /// The class definition.
    pub fn class(&self) -> &'static ClassDef {
        self.class
    }

    /// Whether this object was parsed with strict validation.
    pub fn strict_validation(&self) -> bool {
        self.strict
    }

    /// Parser messages.
    pub fn messages(&self) -> &Messages {
        &self.messages
    }

    /// Mutable parser messages, for callers that add their own (v4's update
    /// handlers do).
    pub fn messages_mut(&mut self) -> &mut Messages {
        &mut self.messages
    }

    /// `_object_data`: attributes in text order.
    pub fn object_data(&self) -> &[ObjectAttr] {
        &self.object_data
    }

    /// `parsed_data`, in insertion order.
    pub fn parsed_data(&self) -> &[(&'static str, Value)] {
        &self.parsed_data
    }

    /// One `parsed_data` entry.
    pub fn parsed_value(&self, name: &str) -> Option<&Value> {
        self.parsed_data
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v)
    }

    fn parsed_value_mut(&mut self, name: &str) -> Option<&mut Value> {
        self.parsed_data
            .iter_mut()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v)
    }

    /// `pk()`: the primary key, upper-cased; composite keys concatenated.
    pub fn pk(&self) -> String {
        let mut out = String::new();
        for name in self.class.pk_fields() {
            if let Some(Value::Str(s)) = self.parsed_value(name) {
                out.push_str(s);
            }
        }
        py::upper(&out).into_owned()
    }

    /// `source()`.
    pub fn source(&self) -> Result<&str, ParseError> {
        match self.parsed_value("source") {
            Some(Value::Str(s)) => Ok(s),
            _ => Err(ParseError::Uncaught(messages::NO_KNOWN_SOURCE.to_owned())),
        }
    }

    /// `ip_version()`.
    pub fn ip_version(&self) -> Option<u8> {
        self.ip_first.map(|ip| ip.version())
    }

    /// `is_route`.
    pub fn is_route(&self) -> bool {
        self.class.is_route
    }

    /// `referred_strong_objects()`: `(attribute, referred classes, values)`
    /// for every strong reference attribute with a value.
    pub fn referred_strong_objects(&self) -> Vec<(&'static str, &'static [&'static str], &Value)> {
        self.class
            .fields
            .iter()
            .filter(|f| f.kind.strong())
            .filter_map(|f| {
                let data = self.parsed_value(f.name)?;
                data.is_truthy()
                    .then_some((f.name, f.kind.referring(), data))
            })
            .collect()
    }

    /// `references_strong_inbound()`, sorted.
    pub fn references_strong_inbound(&self) -> Vec<&'static str> {
        classes::references_strong_inbound(self.class.name)
    }

    /// `render_rpsl_text()`: the object text in v4's layout.
    pub fn render_rpsl_text(&self) -> String {
        self.render(None, false)
    }

    /// `render_rpsl_text(last_modified)`: as [`Self::render_rpsl_text`], but
    /// for authoritative sources without
    /// `authoritative_retain_last_modified`, existing `last-modified` lines
    /// are replaced with one for `last_modified` (Unix seconds, UTC).
    pub fn render_rpsl_text_with_last_modified(
        &self,
        last_modified: i64,
        settings: &RpslSettings,
    ) -> String {
        let source = self.source().map(|s| s.to_owned()).unwrap_or_default();
        let s = settings.sources.get(&source).copied().unwrap_or_default();
        let replace = s.authoritative && !s.authoritative_retain_last_modified;
        let mut out = self.render(Some(last_modified), replace);
        if replace {
            out.push_str(&format!(
                "{:<width$}",
                "last-modified:",
                width = RPSL_ATTRIBUTE_TEXT_WIDTH
            ));
            out.push_str(&format_last_modified(last_modified));
            out.push('\n');
        }
        out
    }

    fn render(&self, _last_modified: Option<i64>, drop_last_modified: bool) -> String {
        let mut output =
            String::with_capacity(self.object_data.iter().map(|a| a.value.len() + 20).sum());
        for attr in &self.object_data {
            if drop_last_modified && attr.name == "last-modified" {
                continue;
            }
            let lines: Vec<&str> = splitline_unicodesafe(&attr.value).collect();
            if lines.is_empty() {
                output.push_str(&attr.name);
                output.push_str(":\n");
            }
            for (idx, line) in lines.iter().enumerate() {
                if idx == 0 {
                    let label = format!("{}:", attr.name);
                    output.push_str(&label);
                    let width = label.chars().count();
                    for _ in width..RPSL_ATTRIBUTE_TEXT_WIDTH {
                        output.push(' ');
                    }
                    output.push_str(line);
                } else {
                    let mut c = attr.continuation_chars.get(idx - 1).copied().unwrap_or('+');
                    if line.is_empty() {
                        c = '+';
                    }
                    output.push(c);
                    for _ in 0..RPSL_ATTRIBUTE_TEXT_WIDTH - 1 {
                        output.push(' ');
                    }
                    output.push_str(line);
                }
                output.push('\n');
            }
        }
        output
    }
}

/// `RPSLKeyCert.format_fingerprint`: groups of four, with a double space in
/// the middle.
pub fn format_fingerprint(fingerprint: &str) -> String {
    let chars: Vec<char> = fingerprint.chars().collect();
    let mut parts: Vec<String> = Vec::new();
    for idx in (0..40).step_by(4) {
        let end = (idx + 4).min(chars.len());
        let start = idx.min(chars.len());
        parts.push(chars[start..end].iter().collect());
        if idx == 16 {
            parts.push(String::new());
        }
    }
    parts.join(" ")
}

/// `datetime.isoformat()` of a UTC timestamp without microseconds, with
/// `+00:00` written as `Z`.
fn format_last_modified(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

impl fmt::Display for RpslObject {
    /// `repr()`: `class/pk/source`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = self
            .parsed_value("source")
            .and_then(Value::as_str)
            .unwrap_or("");
        write!(f, "{}/{}/{}", self.class.name, self.pk(), source)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn last_modified_format() {
        assert_eq!(format_last_modified(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_last_modified(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn fingerprint_format() {
        assert_eq!(
            format_fingerprint("877D9DF46EFF0FCD68E24E5E957CA8263B0CA1E0"),
            "877D 9DF4 6EFF 0FCD 68E2  4E5E 957C A826 3B0C A1E0"
        );
    }

    #[test]
    fn normalises_like_v4() {
        assert_eq!(normalise_rpsl_value("192.0.2.0 # c"), "192.0.2.0");
        assert_eq!(
            normalise_rpsl_value("192.0.2.0 # c1\n- # c2\n192.0.2.1 # c3\n# c4"),
            "192.0.2.0,-,192.0.2.1"
        );
    }
}
