//! JSON as v4's HTTP responses write it, and as Python's `json` reads it.
//!
//! Starlette's `JSONResponse` renders with `json.dumps(content,
//! ensure_ascii=False, allow_nan=False, indent=None, separators=(",", ":"))`:
//! keys in insertion order, no spaces, non-ASCII as is. String escaping is
//! then the same as `serde_json`'s. Objects decoded from client JSON keep
//! their key order ([`PyJson`]), as Python dicts do.

use std::fmt::Write as _;

/// A JSON object being written, keys in insertion order.
#[derive(Debug, Clone, Default)]
pub struct Obj {
    fields: Vec<(String, String)>,
}

/// A JSON string literal as `json.dumps(s, ensure_ascii=False)` writes it.
pub fn string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned())
}

impl Obj {
    /// An empty object.
    pub fn new() -> Self {
        Obj::default()
    }

    /// A raw, already serialised value.
    pub fn raw(&mut self, k: &str, v: &str) {
        self.fields.push((k.to_owned(), v.to_owned()));
    }

    /// A boolean.
    pub fn bool(&mut self, k: &str, v: bool) {
        self.raw(k, if v { "true" } else { "false" });
    }

    /// An integer.
    pub fn int(&mut self, k: &str, v: usize) {
        self.raw(k, &v.to_string());
    }

    /// A string.
    pub fn str(&mut self, k: &str, v: &str) {
        self.raw(k, &string(v));
    }

    /// A string or `null`.
    pub fn opt_str(&mut self, k: &str, v: Option<String>) {
        match v {
            Some(s) => self.str(k, &s),
            None => self.raw(k, "null"),
        }
    }

    /// A list of strings.
    pub fn str_list(&mut self, k: &str, v: &[String]) {
        let items: Vec<String> = v.iter().map(|s| string(s)).collect();
        self.raw(k, &format!("[{}]", items.join(",")));
    }

    /// A nested object.
    pub fn obj(&mut self, k: &str, v: &Obj) {
        self.raw(k, &v.finish());
    }

    /// A list of objects.
    pub fn obj_list(&mut self, k: &str, v: &[Obj]) {
        let items: Vec<String> = v.iter().map(Obj::finish).collect();
        self.raw(k, &format!("[{}]", items.join(",")));
    }

    /// The serialised object.
    pub fn finish(&self) -> String {
        let mut out = String::from("{");
        for (i, (k, v)) in self.fields.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(out, "{}:{v}", string(k));
        }
        out.push('}');
        out
    }
}

/// A JSON value as `json.loads` returns it: objects keep their key order
/// (a repeated key keeps its first position and its last value).
#[derive(Debug, Clone, PartialEq)]
pub enum PyJson {
    /// `None`
    Null,
    /// `True`/`False`
    Bool(bool),
    /// An int or float.
    Number(serde_json::Number),
    /// A str.
    Str(String),
    /// A list.
    List(Vec<PyJson>),
    /// A dict.
    Dict(Vec<(String, PyJson)>),
}

impl<'de> serde::Deserialize<'de> for PyJson {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = PyJson;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON")
            }
            fn visit_unit<E>(self) -> Result<PyJson, E> {
                Ok(PyJson::Null)
            }
            fn visit_bool<E>(self, v: bool) -> Result<PyJson, E> {
                Ok(PyJson::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<PyJson, E> {
                Ok(PyJson::Number(v.into()))
            }
            fn visit_u64<E>(self, v: u64) -> Result<PyJson, E> {
                Ok(PyJson::Number(v.into()))
            }
            fn visit_f64<E>(self, v: f64) -> Result<PyJson, E> {
                Ok(serde_json::Number::from_f64(v).map_or(PyJson::Null, PyJson::Number))
            }
            fn visit_str<E>(self, v: &str) -> Result<PyJson, E> {
                Ok(PyJson::Str(v.to_owned()))
            }
            fn visit_string<E>(self, v: String) -> Result<PyJson, E> {
                Ok(PyJson::Str(v))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<PyJson, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = a.next_element()? {
                    out.push(v);
                }
                Ok(PyJson::List(out))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> Result<PyJson, A::Error> {
                let mut out: Vec<(String, PyJson)> = Vec::new();
                while let Some((k, v)) = a.next_entry::<String, PyJson>()? {
                    match out.iter_mut().find(|(ek, _)| *ek == k) {
                        Some(e) => e.1 = v,
                        None => out.push((k, v)),
                    }
                }
                Ok(PyJson::Dict(out))
            }
        }
        d.deserialize_any(V)
    }
}

impl PyJson {
    /// `json.dumps(value, ensure_ascii=False, separators=(",", ":"))`.
    pub fn dumps(&self) -> String {
        match self {
            PyJson::Null => "null".to_owned(),
            PyJson::Bool(b) => if *b { "true" } else { "false" }.to_owned(),
            PyJson::Number(n) => n.to_string(),
            PyJson::Str(s) => string(s),
            PyJson::List(l) => format!(
                "[{}]",
                l.iter().map(PyJson::dumps).collect::<Vec<_>>().join(",")
            ),
            PyJson::Dict(d) => format!(
                "{{{}}}",
                d.iter()
                    .map(|(k, v)| format!("{}:{}", string(k), v.dumps()))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }

    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            PyJson::Null => false,
            PyJson::Bool(b) => *b,
            PyJson::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
            PyJson::Str(s) => !s.is_empty(),
            PyJson::List(l) => !l.is_empty(),
            PyJson::Dict(d) => !d.is_empty(),
        }
    }

    /// `str(value)`.
    pub fn py_str(&self) -> String {
        match self {
            PyJson::Str(s) => s.clone(),
            other => other.py_repr(),
        }
    }

    /// `repr(value)`.
    pub fn py_repr(&self) -> String {
        match self {
            PyJson::Null => "None".to_owned(),
            PyJson::Bool(b) => if *b { "True" } else { "False" }.to_owned(),
            PyJson::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
                (Some(i), _, _) => i.to_string(),
                (_, Some(u), _) => u.to_string(),
                (_, _, Some(f)) => py_float_repr(f),
                _ => n.to_string(),
            },
            PyJson::Str(s) => py_str_repr(s),
            PyJson::List(l) => format!(
                "[{}]",
                l.iter().map(PyJson::py_repr).collect::<Vec<_>>().join(", ")
            ),
            PyJson::Dict(d) => format!(
                "{{{}}}",
                d.iter()
                    .map(|(k, v)| format!("{}: {}", py_str_repr(k), v.py_repr()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

/// `repr(float)` for the common cases.
fn py_float_repr(f: f64) -> String {
    if f.is_finite() && f == f.trunc() && f.abs() < 1e16 {
        format!("{f:.1}")
    } else {
        let s = format!("{f}");
        if s.contains('e') {
            s.replace("e", "e+").replace("e+-", "e-")
        } else {
            s
        }
    }
}

/// `repr(str)`.
pub fn py_str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
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
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dicts_keep_key_order() {
        let v: PyJson = serde_json::from_str(r#"{"b":1,"a":"x","b":2}"#).unwrap_or(PyJson::Null);
        assert_eq!(v.dumps(), r#"{"b":2,"a":"x"}"#);
        assert_eq!(v.py_repr(), "{'b': 2, 'a': 'x'}");
    }

    #[test]
    fn strings_like_json_dumps() {
        assert_eq!(string("a\"b\\c\nü\u{1}"), "\"a\\\"b\\\\c\\nü\\u0001\"");
    }
}
