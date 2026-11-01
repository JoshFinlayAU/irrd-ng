//! The `/v1/submit/` and `/v1/suspension/` request bodies: Python's
//! `json.loads` (with its error texts), then pydantic 2.12's validation of
//! `RPSLChangeSubmission` and `RPSLSuspensionSubmission`
//! (`irrd/utils/validators.py`), with pydantic's error texts. Both become
//! the 400 response body in v4.

use crate::handler::{ChangeObject, Submission};
use crate::json::{PyJson, py_str_repr};
use crate::request::SuspensionType;

/// The pydantic release pinned by v4 4.5.4, which appears in its error URLs.
const PYDANTIC_URL_VERSION: &str = "2.12";

/// Why a body was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyError {
    /// A 400 with this text (`JSONDecodeError` or `ValidationError`).
    BadRequest(String),
    /// An exception v4 does not catch: a 500.
    Internal(String),
}

// ---------------------------------------------------------------------------
// json.loads
// ---------------------------------------------------------------------------

struct JsonParser<'a> {
    s: &'a [char],
    pos: usize,
}

type JResult<T> = Result<T, (String, usize)>;

impl JsonParser<'_> {
    fn ws(&mut self) {
        while self.pos < self.s.len() && matches!(self.s[self.pos], ' ' | '\t' | '\n' | '\r') {
            self.pos += 1;
        }
    }

    fn value(&mut self) -> JResult<PyJson> {
        let Some(&c) = self.s.get(self.pos) else {
            return Err(("Expecting value".into(), self.pos));
        };
        match c {
            '"' => {
                self.pos += 1;
                Ok(PyJson::Str(self.string()?))
            }
            '{' => self.object(),
            '[' => self.array(),
            'n' if self.lit("null") => Ok(PyJson::Null),
            't' if self.lit("true") => Ok(PyJson::Bool(true)),
            'f' if self.lit("false") => Ok(PyJson::Bool(false)),
            'N' if self.lit("NaN") => Ok(PyJson::Null),
            'I' if self.lit("Infinity") => Ok(PyJson::Null),
            '-' if self.lit("-Infinity") => Ok(PyJson::Null),
            '-' | '0'..='9' => self.number(),
            _ => Err(("Expecting value".into(), self.pos)),
        }
    }

    fn lit(&mut self, l: &str) -> bool {
        let n = l.chars().count();
        if self.pos + n <= self.s.len()
            && self.s[self.pos..self.pos + n].iter().copied().eq(l.chars())
        {
            self.pos += n;
            return true;
        }
        false
    }

    fn number(&mut self) -> JResult<PyJson> {
        let start = self.pos;
        let digits = |p: &mut Self| {
            let s = p.pos;
            while p.pos < p.s.len() && p.s[p.pos].is_ascii_digit() {
                p.pos += 1;
            }
            p.pos > s
        };
        if self.s.get(self.pos) == Some(&'-') {
            self.pos += 1;
        }
        if self.s.get(self.pos) == Some(&'0') {
            self.pos += 1;
        } else if !digits(self) {
            self.pos = start;
            return Err(("Expecting value".into(), start));
        }
        let mut float = false;
        if self.s.get(self.pos) == Some(&'.')
            && self.s.get(self.pos + 1).is_some_and(char::is_ascii_digit)
        {
            self.pos += 1;
            digits(self);
            float = true;
        }
        if matches!(self.s.get(self.pos), Some('e' | 'E')) {
            let save = self.pos;
            self.pos += 1;
            if matches!(self.s.get(self.pos), Some('+' | '-')) {
                self.pos += 1;
            }
            if digits(self) {
                float = true;
            } else {
                self.pos = save;
            }
        }
        let text: String = self.s[start..self.pos].iter().collect();
        let n = if float {
            text.parse::<f64>()
                .ok()
                .and_then(serde_json::Number::from_f64)
        } else {
            text.parse::<i64>()
                .ok()
                .map(serde_json::Number::from)
                .or_else(|| text.parse::<u64>().ok().map(serde_json::Number::from))
                .or_else(|| {
                    text.parse::<f64>()
                        .ok()
                        .and_then(serde_json::Number::from_f64)
                })
        };
        Ok(n.map_or(PyJson::Null, PyJson::Number))
    }

    fn string(&mut self) -> JResult<String> {
        let begin = self.pos - 1;
        let mut out = String::new();
        loop {
            let Some(&c) = self.s.get(self.pos) else {
                return Err(("Unterminated string starting at".into(), begin));
            };
            match c {
                '"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                '\\' => {
                    let Some(&e) = self.s.get(self.pos + 1) else {
                        return Err(("Unterminated string starting at".into(), begin));
                    };
                    let simple = match e {
                        '"' => Some('"'),
                        '\\' => Some('\\'),
                        '/' => Some('/'),
                        'b' => Some('\u{8}'),
                        'f' => Some('\u{c}'),
                        'n' => Some('\n'),
                        'r' => Some('\r'),
                        't' => Some('\t'),
                        _ => None,
                    };
                    if let Some(ch) = simple {
                        out.push(ch);
                        self.pos += 2;
                        continue;
                    }
                    if e != 'u' {
                        return Err(("Invalid \\escape".into(), self.pos));
                    }
                    let hex = |p: &Self, at: usize| -> Option<u32> {
                        let h: String = p.s.get(at..at + 4)?.iter().collect();
                        if h.len() == 4 && h.chars().all(|c| c.is_ascii_hexdigit()) {
                            u32::from_str_radix(&h, 16).ok()
                        } else {
                            None
                        }
                    };
                    let Some(u) = hex(self, self.pos + 2) else {
                        return Err(("Invalid \\uXXXX escape".into(), self.pos + 1));
                    };
                    self.pos += 6;
                    if (0xd800..0xdc00).contains(&u)
                        && self.s.get(self.pos) == Some(&'\\')
                        && self.s.get(self.pos + 1) == Some(&'u')
                        && let Some(l) = hex(self, self.pos + 2)
                        && (0xdc00..0xe000).contains(&l)
                    {
                        self.pos += 6;
                        let v = 0x10000 + ((u - 0xd800) << 10) + (l - 0xdc00);
                        out.push(char::from_u32(v).unwrap_or('\u{fffd}'));
                    } else {
                        out.push(char::from_u32(u).unwrap_or('\u{fffd}'));
                    }
                }
                c if (c as u32) < 0x20 => {
                    return Err(("Invalid control character at".into(), self.pos));
                }
                c => {
                    out.push(c);
                    self.pos += 1;
                }
            }
        }
    }

    fn object(&mut self) -> JResult<PyJson> {
        self.pos += 1;
        let mut out: Vec<(String, PyJson)> = Vec::new();
        self.ws();
        if self.s.get(self.pos) == Some(&'}') {
            self.pos += 1;
            return Ok(PyJson::Dict(out));
        }
        loop {
            if self.s.get(self.pos) != Some(&'"') {
                return Err((
                    "Expecting property name enclosed in double quotes".into(),
                    self.pos,
                ));
            }
            self.pos += 1;
            let key = self.string()?;
            self.ws();
            if self.s.get(self.pos) != Some(&':') {
                return Err(("Expecting ':' delimiter".into(), self.pos));
            }
            self.pos += 1;
            self.ws();
            let v = self.value()?;
            match out.iter_mut().find(|(k, _)| *k == key) {
                Some(e) => e.1 = v,
                None => out.push((key, v)),
            }
            self.ws();
            match self.s.get(self.pos) {
                Some('}') => {
                    self.pos += 1;
                    return Ok(PyJson::Dict(out));
                }
                Some(',') => {
                    let comma = self.pos;
                    self.pos += 1;
                    self.ws();
                    if self.s.get(self.pos) == Some(&'}') {
                        return Err(("Illegal trailing comma before end of object".into(), comma));
                    }
                }
                _ => return Err(("Expecting ',' delimiter".into(), self.pos)),
            }
        }
    }

    fn array(&mut self) -> JResult<PyJson> {
        self.pos += 1;
        let mut out = Vec::new();
        self.ws();
        if self.s.get(self.pos) == Some(&']') {
            self.pos += 1;
            return Ok(PyJson::List(out));
        }
        loop {
            out.push(self.value()?);
            self.ws();
            match self.s.get(self.pos) {
                Some(']') => {
                    self.pos += 1;
                    return Ok(PyJson::List(out));
                }
                Some(',') => {
                    let comma = self.pos;
                    self.pos += 1;
                    self.ws();
                    if self.s.get(self.pos) == Some(&']') {
                        return Err(("Illegal trailing comma before end of array".into(), comma));
                    }
                }
                _ => return Err(("Expecting ',' delimiter".into(), self.pos)),
            }
        }
    }
}

/// `json.loads(body)` on the raw request body. A body that is not UTF-8
/// raises `UnicodeDecodeError`, which v4 does not catch.
pub fn json_loads(body: &[u8]) -> Result<PyJson, BodyError> {
    let text = std::str::from_utf8(body).map_err(|e| BodyError::Internal(e.to_string()))?;
    let chars: Vec<char> = text.chars().collect();
    let err = |msg: String, pos: usize| {
        let before = &chars[..pos.min(chars.len())];
        let lineno = before.iter().filter(|c| **c == '\n').count() + 1;
        let colno = match before.iter().rposition(|c| *c == '\n') {
            Some(nl) => pos - nl,
            None => pos + 1,
        };
        BodyError::BadRequest(format!("{msg}: line {lineno} column {colno} (char {pos})"))
    };
    if chars.first() == Some(&'\u{feff}') {
        return Err(err(
            "Unexpected UTF-8 BOM (decode using utf-8-sig)".into(),
            0,
        ));
    }
    let mut p = JsonParser { s: &chars, pos: 0 };
    p.ws();
    let v = p.value().map_err(|(m, pos)| err(m, pos))?;
    p.ws();
    if p.pos != chars.len() {
        return Err(err("Extra data".into(), p.pos));
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// pydantic
// ---------------------------------------------------------------------------

struct ErrorItem {
    loc: Vec<String>,
    msg: String,
    kind: &'static str,
    input: PyJson,
}

fn input_type(v: &PyJson) -> &'static str {
    match v {
        PyJson::Null => "NoneType",
        PyJson::Bool(_) => "bool",
        PyJson::Number(n) if n.is_f64() => "float",
        PyJson::Number(_) => "int",
        PyJson::Str(_) => "str",
        PyJson::List(_) => "list",
        PyJson::Dict(_) => "dict",
    }
}

/// pydantic_core's `truncate_input_value`: reprs over 50 characters keep
/// the first 25 and the last 24.
fn truncated_repr(v: &PyJson) -> String {
    let r = v.py_repr();
    let chars: Vec<char> = r.chars().collect();
    if chars.len() > 50 {
        let head: String = chars[..25].iter().collect();
        let tail: String = chars[chars.len() - 24..].iter().collect();
        format!("{head}...{tail}")
    } else {
        r
    }
}

fn render_errors(model: &str, errors: &[ErrorItem]) -> String {
    let mut out = format!(
        "{} validation error{} for {model}",
        errors.len(),
        if errors.len() == 1 { "" } else { "s" }
    );
    for e in errors {
        if !e.loc.is_empty() {
            out.push('\n');
            out.push_str(&e.loc.join("."));
        }
        out.push_str(&format!(
            "\n  {} [type={}, input_value={}, input_type={}]\n    For further information visit https://errors.pydantic.dev/{PYDANTIC_URL_VERSION}/v/{}",
            e.msg,
            e.kind,
            truncated_repr(&e.input),
            input_type(&e.input),
            e.kind
        ));
    }
    out
}

fn loc(base: &[String], more: &str) -> Vec<String> {
    let mut l = base.to_vec();
    l.push(more.to_owned());
    l
}

fn missing(errors: &mut Vec<ErrorItem>, at: Vec<String>, input: &PyJson) {
    errors.push(ErrorItem {
        loc: at,
        msg: "Field required".into(),
        kind: "missing",
        input: input.clone(),
    });
}

fn want_str(errors: &mut Vec<ErrorItem>, at: Vec<String>, v: &PyJson) -> Option<String> {
    match v {
        PyJson::Str(s) => Some(s.clone()),
        other => {
            errors.push(ErrorItem {
                loc: at,
                msg: "Input should be a valid string".into(),
                kind: "string_type",
                input: other.clone(),
            });
            None
        }
    }
}

fn want_list<'v>(
    errors: &mut Vec<ErrorItem>,
    at: Vec<String>,
    v: &'v PyJson,
) -> Option<&'v [PyJson]> {
    match v {
        PyJson::List(l) => Some(l),
        other => {
            errors.push(ErrorItem {
                loc: at,
                msg: "Input should be a valid list".into(),
                kind: "list_type",
                input: other.clone(),
            });
            None
        }
    }
}

fn want_str_list(errors: &mut Vec<ErrorItem>, at: Vec<String>, v: &PyJson) -> Option<Vec<String>> {
    let items = want_list(errors, at.clone(), v)?;
    let before = errors.len();
    let out: Vec<Option<String>> = items
        .iter()
        .enumerate()
        .map(|(i, item)| want_str(errors, loc(&at, &i.to_string()), item))
        .collect();
    if errors.len() > before {
        return None;
    }
    Some(out.into_iter().flatten().collect())
}

fn model_type(errors: &mut Vec<ErrorItem>, at: Vec<String>, model: &str, v: &PyJson) {
    errors.push(ErrorItem {
        loc: at,
        msg: format!("Input should be a valid dictionary or instance of {model}"),
        kind: "model_type",
        input: v.clone(),
    });
}

fn get<'d>(d: &'d [(String, PyJson)], k: &str) -> Option<&'d PyJson> {
    d.iter().find(|(key, _)| key == k).map(|(_, v)| v)
}

/// A validated `RPSLChangeSubmission`.
#[derive(Debug, Clone)]
pub struct ChangeSubmission {
    /// The objects as text.
    pub objects: Vec<ChangeObject>,
    /// `passwords`
    pub passwords: Vec<String>,
    /// `override`
    pub override_: Option<String>,
    /// `api_keys`
    pub api_keys: Vec<String>,
    /// `delete_reason`
    pub delete_reason: String,
}

impl ChangeSubmission {
    /// `load_change_submission(data, delete=...)` input.
    pub fn into_submission(self, delete: bool, remote_ip: Option<String>) -> Submission {
        Submission::Change {
            objects: self.objects,
            passwords: self.passwords,
            override_: self.override_,
            api_keys: self.api_keys,
            delete_reason: delete.then_some(self.delete_reason),
            remote_ip,
        }
    }
}

/// `RPSLChangeSubmission.model_validate(json)`
pub fn validate_change_submission(v: &PyJson) -> Result<ChangeSubmission, BodyError> {
    const MODEL: &str = "RPSLChangeSubmission";
    let mut errors = Vec::new();
    let PyJson::Dict(d) = v else {
        model_type(&mut errors, Vec::new(), MODEL, v);
        return Err(BodyError::BadRequest(render_errors(MODEL, &errors)));
    };
    let mut objects = Vec::new();
    match get(d, "objects") {
        None => missing(&mut errors, vec!["objects".into()], v),
        Some(list) => {
            if let Some(items) = want_list(&mut errors, vec!["objects".into()], list) {
                for (i, item) in items.iter().enumerate() {
                    let at = vec!["objects".to_owned(), i.to_string()];
                    if let Some(o) = validate_change_object(&mut errors, at, item)? {
                        objects.push(o);
                    }
                }
            }
        }
    }
    let passwords = match get(d, "passwords") {
        None => Some(Vec::new()),
        Some(p) => want_str_list(&mut errors, vec!["passwords".into()], p),
    };
    let override_ = match get(d, "override") {
        None | Some(PyJson::Null) => Some(None),
        Some(o) => want_str(&mut errors, vec!["override".into()], o).map(Some),
    };
    let api_keys = match get(d, "api_keys") {
        None => Some(Vec::new()),
        Some(p) => want_str_list(&mut errors, vec!["api_keys".into()], p),
    };
    let delete_reason = match get(d, "delete_reason") {
        None => Some("(No reason provided)".to_owned()),
        Some(r) => want_str(&mut errors, vec!["delete_reason".into()], r),
    };
    if !errors.is_empty() {
        return Err(BodyError::BadRequest(render_errors(MODEL, &errors)));
    }
    Ok(ChangeSubmission {
        objects,
        passwords: passwords.unwrap_or_default(),
        override_: override_.flatten(),
        api_keys: api_keys.unwrap_or_default(),
        delete_reason: delete_reason.unwrap_or_default(),
    })
}

fn validate_change_object(
    errors: &mut Vec<ErrorItem>,
    at: Vec<String>,
    v: &PyJson,
) -> Result<Option<ChangeObject>, BodyError> {
    // The "before" model validator calls values.get() on whatever it gets.
    let PyJson::Dict(d) = v else {
        let t = match v {
            PyJson::Null => "NoneType",
            PyJson::Bool(_) => "bool",
            PyJson::Number(n) if n.is_f64() => "float",
            PyJson::Number(_) => "int",
            PyJson::Str(_) => "str",
            PyJson::List(_) => "list",
            PyJson::Dict(_) => "dict",
        };
        return Err(BodyError::Internal(format!(
            "'{t}' object has no attribute 'get'"
        )));
    };
    let text = get(d, "object_text");
    let attrs = get(d, "attributes");
    if text.is_some_and(PyJson::truthy) == attrs.is_some_and(PyJson::truthy) {
        errors.push(ErrorItem {
            loc: at,
            msg: "Value error, You must describe each object with either \"object_text\" or \"attributes\"".into(),
            kind: "value_error",
            input: v.clone(),
        });
        return Ok(None);
    }
    let before = errors.len();
    let object_text = match text {
        None | Some(PyJson::Null) => None,
        Some(t) => want_str(errors, loc(&at, "object_text"), t),
    };
    let mut attributes: Option<Vec<(String, String)>> = None;
    match attrs {
        None | Some(PyJson::Null) => {}
        Some(a) => {
            if let Some(items) = want_list(errors, loc(&at, "attributes"), a) {
                let mut out = Vec::new();
                for (i, item) in items.iter().enumerate() {
                    let iat = loc(&loc(&at, "attributes"), &i.to_string());
                    let PyJson::Dict(ad) = item else {
                        model_type(errors, iat, "RPSLChangeSubmissionObjectAttribute", item);
                        continue;
                    };
                    let name = match get(ad, "name") {
                        None => {
                            missing(errors, loc(&iat, "name"), item);
                            None
                        }
                        Some(n) => want_str(errors, loc(&iat, "name"), n),
                    };
                    let value = match get(ad, "value") {
                        None => {
                            missing(errors, loc(&iat, "value"), item);
                            None
                        }
                        Some(PyJson::Str(s)) => Some(s.clone()),
                        Some(other) => {
                            // str | list[str]: both branches report.
                            let vat = loc(&iat, "value");
                            errors.push(ErrorItem {
                                loc: loc(&vat, "str"),
                                msg: "Input should be a valid string".into(),
                                kind: "string_type",
                                input: other.clone(),
                            });
                            let lat = loc(&vat, "list[str]");
                            let before_list = errors.len();
                            let list = want_str_list(errors, lat, other);
                            if let Some(l) = list {
                                // Valid as a list after all: drop the str error.
                                errors.truncate(before_list - 1);
                                Some(l.join(", "))
                            } else {
                                None
                            }
                        }
                    };
                    if let (Some(n), Some(v)) = (name, value) {
                        out.push((n, v));
                    }
                }
                attributes = Some(out);
            }
        }
    }
    if errors.len() > before {
        return Ok(None);
    }
    let text = match attributes.filter(|a| !a.is_empty()) {
        Some(a) => {
            let lines: Vec<String> = a.iter().map(|(n, v)| format!("{n}: {v}")).collect();
            lines.join("\n") + "\n"
        }
        None => object_text.unwrap_or_default(),
    };
    Ok(Some(ChangeObject { text }))
}

/// `RPSLSuspensionSubmission.model_validate(json)`
pub fn validate_suspension_submission(v: &PyJson) -> Result<Submission, BodyError> {
    const MODEL: &str = "RPSLSuspensionSubmission";
    let mut errors = Vec::new();
    let PyJson::Dict(d) = v else {
        model_type(&mut errors, Vec::new(), MODEL, v);
        return Err(BodyError::BadRequest(render_errors(MODEL, &errors)));
    };
    let mut objects = Vec::new();
    match get(d, "objects") {
        None => missing(&mut errors, vec!["objects".into()], v),
        Some(list) => {
            if let Some(items) = want_list(&mut errors, vec!["objects".into()], list) {
                for (i, item) in items.iter().enumerate() {
                    let at = vec!["objects".to_owned(), i.to_string()];
                    let PyJson::Dict(od) = item else {
                        model_type(&mut errors, at, "RPSLSuspensionSubmissionObject", item);
                        continue;
                    };
                    let field = |errors: &mut Vec<ErrorItem>, name: &str| match get(od, name) {
                        None => {
                            missing(errors, loc(&at, name), item);
                            None
                        }
                        Some(x) => want_str(errors, loc(&at, name), x),
                    };
                    let mntner = field(&mut errors, "mntner");
                    let source = field(&mut errors, "source");
                    let request_type = match get(od, "request_type") {
                        None => {
                            missing(&mut errors, loc(&at, "request_type"), item);
                            None
                        }
                        Some(PyJson::Str(s)) if s == "suspend" => Some(SuspensionType::Suspend),
                        Some(PyJson::Str(s)) if s == "reactivate" => {
                            Some(SuspensionType::Reactivate)
                        }
                        Some(other) => {
                            errors.push(ErrorItem {
                                loc: loc(&at, "request_type"),
                                msg: "Input should be 'suspend' or 'reactivate'".into(),
                                kind: "enum",
                                input: other.clone(),
                            });
                            None
                        }
                    };
                    if let (Some(m), Some(s), Some(t)) = (mntner, source, request_type) {
                        objects.push((m, s, t));
                    }
                }
            }
        }
    }
    let override_ = match get(d, "override") {
        None | Some(PyJson::Null) => Some(None),
        Some(o) => want_str(&mut errors, vec!["override".into()], o).map(Some),
    };
    if !errors.is_empty() {
        return Err(BodyError::BadRequest(render_errors(MODEL, &errors)));
    }
    Ok(Submission::Suspension {
        objects,
        override_: override_.flatten(),
    })
}

/// The `X-irrd-metadata` header as v4 reads it: a JSON object, or `{}` when
/// the header is missing or not JSON.
pub fn parse_metadata_header(raw: Option<&[u8]>) -> Result<Vec<(String, PyJson)>, BodyError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    // Starlette decodes header values as Latin-1.
    let text: String = raw.iter().map(|&b| b as char).collect();
    match json_loads(text.as_bytes()) {
        Ok(PyJson::Dict(d)) => Ok(d),
        // request_meta[...] = host on anything else raises TypeError.
        Ok(other) => Err(BodyError::Internal(format!(
            "'{}' object does not support item assignment",
            input_type(&other)
        ))),
        Err(BodyError::BadRequest(_)) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// `repr()` of a string, for messages that embed one.
pub fn repr(s: &str) -> String {
    py_str_repr(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(body: &str) -> String {
        match json_loads(body.as_bytes()).and_then(|v| validate_change_submission(&v)) {
            Err(BodyError::BadRequest(s)) => s,
            other => format!("{other:?}"),
        }
    }

    #[test]
    fn json_errors_like_python() {
        assert_eq!(err(""), "Expecting value: line 1 column 1 (char 0)");
        assert_eq!(
            err("{"),
            "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)"
        );
        assert_eq!(err("{\"a\":"), "Expecting value: line 1 column 6 (char 5)");
        assert_eq!(err("{\"a\":1}x"), "Extra data: line 1 column 8 (char 7)");
        assert_eq!(
            err("[1,]"),
            "Illegal trailing comma before end of array: line 1 column 3 (char 2)"
        );
    }

    #[test]
    fn pydantic_errors_like_v4() {
        assert_eq!(
            err("{}"),
            "1 validation error for RPSLChangeSubmission\nobjects\n  Field required [type=missing, input_value={}, input_type=dict]\n    For further information visit https://errors.pydantic.dev/2.12/v/missing"
        );
        assert_eq!(
            err("[]"),
            "1 validation error for RPSLChangeSubmission\n  Input should be a valid dictionary or instance of RPSLChangeSubmission [type=model_type, input_value=[], input_type=list]\n    For further information visit https://errors.pydantic.dev/2.12/v/model_type"
        );
        assert_eq!(
            err(r#"{"objects": [{"object_text": "a", "attributes": [{"name":"a","value":"b"}]}]}"#),
            "1 validation error for RPSLChangeSubmission\nobjects.0\n  Value error, You must describe each object with either \"object_text\" or \"attributes\" [type=value_error, input_value={'object_text': 'a', 'att...e': 'a', 'value': 'b'}]}, input_type=dict]\n    For further information visit https://errors.pydantic.dev/2.12/v/value_error"
        );
        let e = err(r#"{"objects": [{"attributes": [{"name":"x", "value": ["a", 2]}]}]}"#);
        assert!(e.starts_with(
            "2 validation errors for RPSLChangeSubmission\nobjects.0.attributes.0.value.str\n"
        ));
        assert!(e.contains("\nobjects.0.attributes.0.value.list[str].1\n  Input should be a valid string [type=string_type, input_value=2, input_type=int]"));
        let e = err(
            r#"{"objects": [{"object_text": 5}], "passwords": "x", "override": 3, "api_keys": [1], "delete_reason": null}"#,
        );
        assert!(
            e.starts_with("5 validation errors for RPSLChangeSubmission\nobjects.0.object_text\n")
        );
        assert!(e.contains("\ndelete_reason\n  Input should be a valid string [type=string_type, input_value=None, input_type=NoneType]"));
    }

    #[test]
    fn attributes_become_text() {
        let v = json_loads(br#"{"objects": [{"attributes": [{"name":"person","value":"A"},{"name":"remarks","value":["x","y"]}]}]}"#)
            .unwrap_or(PyJson::Null);
        let s = validate_change_submission(&v).map(|s| s.objects[0].text.clone());
        assert_eq!(s, Ok("person: A\nremarks: x, y\n".to_owned()));
    }

    #[test]
    fn non_dict_objects_raise() {
        let v = json_loads(br#"{"objects": [1]}"#).unwrap_or(PyJson::Null);
        assert!(matches!(
            validate_change_submission(&v),
            Err(BodyError::Internal(m)) if m == "'int' object has no attribute 'get'"
        ));
    }
}
