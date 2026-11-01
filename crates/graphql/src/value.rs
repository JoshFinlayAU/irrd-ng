//! Values as Python sees them: what `json.loads` produces from a request,
//! what resolvers return, and what `json.dumps` writes back.
//!
//! Objects keep insertion order, as Python dicts do. Integers are
//! unbounded in Python; irrd-ng keeps them as `i128` and falls back to
//! their digits beyond that, which is all GraphQL coercion needs (anything
//! that large is rejected with its digits in the message).

use std::fmt::Write as _;

/// A Python value from JSON or a resolver.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `None`
    Null,
    /// `bool`
    Bool(bool),
    /// `int` within `i128`.
    Int(i128),
    /// `int` beyond `i128`, as its decimal digits.
    BigInt(String),
    /// `float`
    Float(f64),
    /// `str`
    Str(String),
    /// `list`
    List(Vec<Value>),
    /// `dict` with string keys, in insertion order.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// `dict.get(key)`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(o) => o.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// `d[key] = value`: replaces in place or appends.
    pub fn set(&mut self, key: &str, value: Value) {
        if let Value::Object(o) = self {
            match o.iter_mut().find(|(k, _)| k == key) {
                Some(e) => e.1 = value,
                None => o.push((key.to_owned(), value)),
            }
        }
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Int(i) => *i != 0,
            Value::BigInt(_) => true,
            Value::Float(f) => *f != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::List(l) => !l.is_empty(),
            Value::Object(o) => !o.is_empty(),
        }
    }

    /// A string value.
    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }
}

// ---- json.loads ----

/// A dict's keys in insertion order, the last value of a repeated key
/// winning in the first key's place, as Python's `dict` does. Small
/// objects are searched; larger ones get a hash index, so an object with
/// many keys costs linear time, not quadratic.
#[derive(Default)]
pub(crate) struct KeyIndex(Option<std::collections::HashMap<String, usize>>);

impl KeyIndex {
    const LINEAR: usize = 16;

    pub(crate) fn insert<V>(&mut self, out: &mut Vec<(String, V)>, k: String, v: V) {
        let found = match &self.0 {
            Some(map) => map.get(&k).copied(),
            None => out.iter().position(|(key, _)| *key == k),
        };
        if let Some(i) = found {
            out[i].1 = v;
            return;
        }
        if let Some(map) = &mut self.0 {
            map.insert(k.clone(), out.len());
        } else if out.len() >= Self::LINEAR {
            let mut map: std::collections::HashMap<String, usize> = out
                .iter()
                .enumerate()
                .map(|(i, (key, _))| (key.clone(), i))
                .collect();
            map.insert(k.clone(), out.len());
            self.0 = Some(map);
        }
        out.push((k, v));
    }
}

/// How deeply arrays and objects may nest. Python's decoder recurses
/// once per level and gives up with a `RecursionError` at its recursion
/// limit; this parser recurses too, and stops well before its stack would
/// run out.
pub const MAX_JSON_DEPTH: usize = 512;

/// Why [`json_loads_checked`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    /// Not valid JSON: Python raises `JSONDecodeError` (a `ValueError`).
    Invalid,
    /// Nested deeper than [`MAX_JSON_DEPTH`]: Python's `RecursionError`,
    /// which v4's callers do not catch.
    TooDeep,
}

/// The `RecursionError` message for [`JsonError::TooDeep`].
pub const JSON_RECURSION_ERROR: &str = "RecursionError: maximum recursion depth exceeded while decoding a JSON array from a unicode string";

/// `json.loads(body)` on request bytes; `None` where Python raises (the
/// caller only needs to know that it failed).
pub fn json_loads(body: &[u8]) -> Option<Value> {
    json_loads_checked(body).ok()
}

/// [`json_loads`], telling a `RecursionError` from invalid JSON.
pub fn json_loads_checked(body: &[u8]) -> Result<Value, JsonError> {
    // json.loads(bytes) detects the encoding; anything but UTF-8 is not
    // worth supporting here and ends in the same "not valid JSON" answer
    // for every realistic client. A UTF-8 BOM is accepted, as Python's
    // detect_encoding() picks utf-8-sig.
    let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    if body.len() >= 2 && (body[0] == 0 || body[1] == 0) {
        return Err(JsonError::Invalid);
    }
    let text = std::str::from_utf8(body).map_err(|_| JsonError::Invalid)?;
    json_loads_str_checked(text)
}

/// `json.loads(text)`.
pub fn json_loads_str(text: &str) -> Option<Value> {
    json_loads_str_checked(text).ok()
}

/// [`json_loads_str`], telling a `RecursionError` from invalid JSON.
pub fn json_loads_str_checked(text: &str) -> Result<Value, JsonError> {
    let chars: Vec<char> = text.chars().collect();
    let mut p = JsonParser {
        s: &chars,
        i: 0,
        depth: 0,
        too_deep: false,
    };
    p.ws();
    let v = p.value();
    if p.too_deep {
        return Err(JsonError::TooDeep);
    }
    let v = v.ok_or(JsonError::Invalid)?;
    p.ws();
    if p.i == chars.len() {
        Ok(v)
    } else {
        Err(JsonError::Invalid)
    }
}

struct JsonParser<'a> {
    s: &'a [char],
    i: usize,
    depth: usize,
    too_deep: bool,
}

impl JsonParser<'_> {
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.i += 1;
        }
    }

    fn lit(&mut self, word: &str) -> bool {
        let w: Vec<char> = word.chars().collect();
        if self.s.len() >= self.i + w.len() && self.s[self.i..self.i + w.len()] == w[..] {
            self.i += w.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self) -> Option<Value> {
        match self.peek()? {
            '{' | '[' => {
                if self.depth >= MAX_JSON_DEPTH {
                    self.too_deep = true;
                    return None;
                }
                self.depth += 1;
                let v = if self.peek() == Some('{') {
                    self.object()
                } else {
                    self.list()
                };
                self.depth -= 1;
                v
            }
            '"' => self.string().map(Value::Str),
            'n' if self.lit("null") => Some(Value::Null),
            't' if self.lit("true") => Some(Value::Bool(true)),
            'f' if self.lit("false") => Some(Value::Bool(false)),
            'N' if self.lit("NaN") => Some(Value::Float(f64::NAN)),
            'I' if self.lit("Infinity") => Some(Value::Float(f64::INFINITY)),
            '-' if self.lit("-Infinity") => Some(Value::Float(f64::NEG_INFINITY)),
            '-' | '0'..='9' => self.number(),
            _ => None,
        }
    }

    fn object(&mut self) -> Option<Value> {
        self.i += 1;
        let mut out: Vec<(String, Value)> = Vec::new();
        let mut index = KeyIndex::default();
        self.ws();
        if self.peek() == Some('}') {
            self.i += 1;
            return Some(Value::Object(out));
        }
        loop {
            self.ws();
            if self.peek() != Some('"') {
                return None;
            }
            let k = self.string()?;
            self.ws();
            if self.peek() != Some(':') {
                return None;
            }
            self.i += 1;
            self.ws();
            let v = self.value()?;
            index.insert(&mut out, k, v);
            self.ws();
            match self.peek()? {
                ',' => self.i += 1,
                '}' => {
                    self.i += 1;
                    return Some(Value::Object(out));
                }
                _ => return None,
            }
        }
    }

    fn list(&mut self) -> Option<Value> {
        self.i += 1;
        let mut out = Vec::new();
        self.ws();
        if self.peek() == Some(']') {
            self.i += 1;
            return Some(Value::List(out));
        }
        loop {
            self.ws();
            out.push(self.value()?);
            self.ws();
            match self.peek()? {
                ',' => self.i += 1,
                ']' => {
                    self.i += 1;
                    return Some(Value::List(out));
                }
                _ => return None,
            }
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..4 {
            let d = self.peek()?.to_digit(16)?;
            v = v * 16 + d;
            self.i += 1;
        }
        Some(v)
    }

    fn string(&mut self) -> Option<String> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                '"' => return Some(out),
                '\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let u = self.hex4()?;
                            if (0xd800..0xdc00).contains(&u)
                                && self.peek() == Some('\\')
                                && self.s.get(self.i + 1) == Some(&'u')
                            {
                                let save = self.i;
                                self.i += 2;
                                let lo = self.hex4()?;
                                if (0xdc00..0xe000).contains(&lo) {
                                    let cp = 0x10000 + ((u - 0xd800) << 10) + (lo - 0xdc00);
                                    out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                                    continue;
                                }
                                self.i = save;
                            }
                            // Python keeps a lone surrogate; Rust strings
                            // cannot hold one.
                            out.push(char::from_u32(u).unwrap_or('\u{fffd}'));
                        }
                        _ => return None,
                    }
                }
                c if (c as u32) < 0x20 => return None,
                c => out.push(c),
            }
        }
    }

    fn number(&mut self) -> Option<Value> {
        let start = self.i;
        if self.peek() == Some('-') {
            self.i += 1;
        }
        match self.peek()? {
            '0' => self.i += 1,
            '1'..='9' => {
                while matches!(self.peek(), Some('0'..='9')) {
                    self.i += 1;
                }
            }
            _ => return None,
        }
        let mut float = false;
        if self.peek() == Some('.') && matches!(self.s.get(self.i + 1), Some('0'..='9')) {
            float = true;
            self.i += 1;
            while matches!(self.peek(), Some('0'..='9')) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            let save = self.i;
            self.i += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.i += 1;
            }
            if matches!(self.peek(), Some('0'..='9')) {
                float = true;
                while matches!(self.peek(), Some('0'..='9')) {
                    self.i += 1;
                }
            } else {
                self.i = save;
            }
        }
        let text: String = self.s[start..self.i].iter().collect();
        if float {
            text.parse::<f64>().ok().map(Value::Float)
        } else {
            Some(int_value(&text))
        }
    }
}

/// An integer from its decimal text (optionally signed).
pub fn int_value(text: &str) -> Value {
    match text.parse::<i128>() {
        Ok(i) => Value::Int(i),
        Err(_) => {
            let (neg, digits) = match text.strip_prefix('-') {
                Some(d) => (true, d),
                None => (false, text.strip_prefix('+').unwrap_or(text)),
            };
            let digits = digits.trim_start_matches('0');
            let digits = if digits.is_empty() { "0" } else { digits };
            Value::BigInt(if neg {
                format!("-{digits}")
            } else {
                digits.to_owned()
            })
        }
    }
}

// ---- json.dumps ----

/// Starlette's `JSONResponse.render()`: `json.dumps(content,
/// ensure_ascii=False, allow_nan=False, indent=None, separators=(",", ":"))`.
pub fn json_dumps(v: &Value) -> String {
    let mut out = String::with_capacity(256);
    dump(v, &mut out, false);
    out
}

/// Starlette's `WebSocket.send_json()`: `json.dumps(data,
/// separators=(",", ":"), ensure_ascii=False)`, which writes non-finite
/// floats as `NaN`, `Infinity` and `-Infinity`.
pub fn json_dumps_allow_nan(v: &Value) -> String {
    let mut out = String::with_capacity(256);
    dump(v, &mut out, true);
    out
}

fn dump(v: &Value, out: &mut String, allow_nan: bool) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Value::BigInt(s) => out.push_str(s),
        Value::Float(f) if allow_nan && f.is_nan() => out.push_str("NaN"),
        Value::Float(f) if allow_nan && f.is_infinite() => {
            out.push_str(if *f > 0.0 { "Infinity" } else { "-Infinity" })
        }
        Value::Float(f) => out.push_str(&float_repr(*f)),
        Value::Str(s) => dump_str(s, out),
        Value::List(l) => {
            out.push('[');
            for (i, x) in l.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                dump(x, out, allow_nan);
            }
            out.push(']');
        }
        Value::Object(o) => {
            out.push('{');
            for (i, (k, x)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                dump_str(k, out);
                out.push(':');
                dump(x, out, allow_nan);
            }
            out.push('}');
        }
    }
}

/// A JSON string as `json.dumps(..., ensure_ascii=False)` writes it.
pub fn dump_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---- repr ----

/// `float.__repr__`: the shortest text that round-trips, in scientific
/// notation when the exponent is below -4 or at least 16.
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".to_owned();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.to_owned();
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0.0" } else { "0.0" }.to_owned();
    }
    // Rust's `{:e}` gives the shortest round-trip digits.
    let sci = format!("{f:e}");
    let (mant, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let neg = mant.starts_with('-');
    let digits: String = mant.chars().filter(char::is_ascii_digit).collect();
    let sign = if neg { "-" } else { "" };
    if !(-4..16).contains(&exp) {
        let (first, rest) = digits.split_at(1);
        let mant = if rest.is_empty() {
            first.to_owned()
        } else {
            format!("{first}.{rest}")
        };
        let esign = if exp < 0 { '-' } else { '+' };
        return format!("{sign}{mant}e{esign}{:02}", exp.abs());
    }
    if exp < 0 {
        let zeros = "0".repeat((-exp - 1) as usize);
        return format!("{sign}0.{zeros}{digits}");
    }
    let int_len = exp as usize + 1;
    if digits.len() <= int_len {
        let pad = "0".repeat(int_len - digits.len());
        format!("{sign}{digits}{pad}.0")
    } else {
        let (a, b) = digits.split_at(int_len);
        format!("{sign}{a}.{b}")
    }
}

/// `repr(str)`.
pub fn str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if is_printable(c) => out.push(c),
            c => {
                let n = c as u32;
                if n < 0x100 {
                    let _ = write!(out, "\\x{n:02x}");
                } else if n < 0x10000 {
                    let _ = write!(out, "\\u{n:04x}");
                } else {
                    let _ = write!(out, "\\U{n:08x}");
                }
            }
        }
    }
    out.push(quote);
    out
}

/// `str.isprintable()` for one character, close enough for repr: control
/// characters, separators other than the space, and unassigned or private
/// code points are not printable.
fn is_printable(c: char) -> bool {
    let n = c as u32;
    if n < 0x20 || n == 0x7f {
        return false;
    }
    if (0x80..0xa0).contains(&n) || n == 0xad {
        return false;
    }
    if matches!(n, 0x2028 | 0x2029 | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x2064 | 0xfeff) {
        return false;
    }
    if (0xe000..=0xf8ff).contains(&n) || (0xd800..=0xdfff).contains(&n) {
        return false;
    }
    if c.is_whitespace() && c != ' ' {
        return false;
    }
    true
}

const MAX_STR_SIZE: usize = 240;
const MAX_LIST_SIZE: usize = 10;

fn trunc_str(s: String) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() > MAX_STR_SIZE {
        let i = (MAX_STR_SIZE - 3) / 2;
        let j = MAX_STR_SIZE - 3 - i;
        let head: String = chars[..i].iter().collect();
        let tail: String = chars[chars.len() - j..].iter().collect();
        format!("{head}...{tail}")
    } else {
        s
    }
}

/// graphql-core's `inspect()`.
pub fn inspect(v: &Value) -> String {
    inspect_rec(v, 0)
}

fn inspect_rec(v: &Value, depth: usize) -> String {
    match v {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Float(f) => float_repr(*f),
        Value::Int(i) => trunc_str(i.to_string()),
        Value::BigInt(s) => trunc_str(s.clone()),
        Value::Str(s) => trunc_str(str_repr(s)),
        Value::List(l) => {
            if l.is_empty() {
                return "[]".to_owned();
            }
            if depth >= 2 {
                return "[...]".to_owned();
            }
            let items = trunc_items(l.len());
            let parts: Vec<String> = items
                .iter()
                .map(|i| match i {
                    Some(i) => inspect_rec(&l[*i], depth + 1),
                    None => "...".to_owned(),
                })
                .collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(o) => {
            if o.is_empty() {
                return "{}".to_owned();
            }
            if depth >= 2 {
                return "{...}".to_owned();
            }
            let items = trunc_items(o.len());
            let parts: Vec<String> = items
                .iter()
                .map(|i| match i {
                    Some(i) => format!(
                        "{}: {}",
                        trunc_str(str_repr(&o[*i].0)),
                        inspect_rec(&o[*i].1, depth + 1)
                    ),
                    None => "...".to_owned(),
                })
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

/// `trunc_list()` as indexes, `None` for the ellipsis.
fn trunc_items(n: usize) -> Vec<Option<usize>> {
    if n > MAX_LIST_SIZE {
        let i = MAX_LIST_SIZE / 2;
        let j = i - 1;
        let mut out: Vec<Option<usize>> = (0..i).map(Some).collect();
        out.push(None);
        out.extend((n - j..n).map(Some));
        out
    } else {
        (0..n).map(Some).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_like_python() {
        assert_eq!(float_repr(1.0), "1.0");
        assert_eq!(float_repr(1.5), "1.5");
        assert_eq!(float_repr(1e16), "1e+16");
        assert_eq!(float_repr(1.5e16), "1.5e+16");
        assert_eq!(float_repr(123456789012345.0), "123456789012345.0");
        assert_eq!(float_repr(0.0001), "0.0001");
        assert_eq!(float_repr(0.00001), "1e-05");
        assert_eq!(float_repr(-2.5e-7), "-2.5e-07");
        assert_eq!(float_repr(0.1), "0.1");
    }

    #[test]
    fn json_like_python() {
        let v = json_loads_str(r#" {"a": 1, "b": [1.0, "xé"], "a": 2, "c": NaN} "#);
        let Some(v) = v else { panic!("parse") };
        assert_eq!(
            json_dumps(&v),
            "{\"a\":2,\"b\":[1.0,\"x\u{e9}\"],\"c\":nan}"
        );
        assert!(json_loads_str("{\"a\":1,}").is_none());
        // Nesting past the limit is Python's RecursionError, not a stack
        // overflow; up to it, the value parses.
        let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(json_loads_str_checked(&deep(MAX_JSON_DEPTH)).is_ok());
        assert_eq!(
            json_loads_str_checked(&deep(MAX_JSON_DEPTH + 1)),
            Err(JsonError::TooDeep)
        );
        assert_eq!(
            json_loads_str_checked(&"[".repeat(1_000_000)),
            Err(JsonError::TooDeep)
        );
        assert_eq!(json_loads_str_checked("[1,"), Err(JsonError::Invalid));
        // Many keys: insertion order kept, a repeated key updated in place.
        let mut text = String::from("{");
        for i in 0..1000 {
            text.push_str(&format!("\"k{i}\": {i}, "));
        }
        text.push_str("\"k3\": -1, \"k999\": -2}");
        let Some(Value::Object(o)) = json_loads_str(&text) else {
            panic!("not an object");
        };
        assert_eq!(o.len(), 1000);
        assert_eq!(o[3], ("k3".to_owned(), Value::Int(-1)));
        assert_eq!(o[999], ("k999".to_owned(), Value::Int(-2)));
        assert_eq!(o[500], ("k500".to_owned(), Value::Int(500)));
        assert!(json_loads_str("01").is_none());
        assert_eq!(
            json_loads_str("123456789012345678901234567890123456789012"),
            Some(Value::BigInt(
                "123456789012345678901234567890123456789012".into()
            ))
        );
        assert!(json_loads_str("\"\u{1}\"").is_none());
    }

    #[test]
    fn inspect_like_graphql_core() {
        let v = Value::List(vec![
            Value::Int(1),
            Value::str("a'b"),
            Value::Null,
            Value::Bool(true),
        ]);
        assert_eq!(inspect(&v), "[1, \"a'b\", None, True]");
        let o = Value::Object(vec![("x".into(), Value::List(vec![Value::List(vec![])]))]);
        assert_eq!(inspect(&o), "{'x': [[]]}");
        let deep = Value::List(vec![Value::List(vec![Value::List(vec![Value::Int(1)])])]);
        assert_eq!(inspect(&deep), "[[[...]]]");
    }
}
