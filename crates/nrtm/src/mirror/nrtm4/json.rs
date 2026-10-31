//! JSON as Python sees it: objects become insertion-ordered dicts (a
//! repeated key keeps its first position and its last value, as `ujson`
//! and `json` do), so a value can be shown with Python's `repr()` in error
//! messages.

use std::fmt;

use config::{Dict, Value};
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

struct PyJson;

impl<'de> DeserializeSeed<'de> for PyJson {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(PyJsonVisitor)
    }
}

struct PyJsonVisitor;

impl<'de> Visitor<'de> for PyJsonVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::int(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Int(num_bigint::BigInt::from(v)))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Value::Float(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::Str(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::Str(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::None)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(PyJson)? {
            out.push(v);
        }
        Ok(Value::List(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut d = Dict::new();
        while let Some(k) = map.next_key::<String>()? {
            let v = map.next_value_seed(PyJson)?;
            d.insert(Value::Str(k), v);
        }
        Ok(Value::Dict(d))
    }
}

/// Parse JSON text into Python values. The error is serde_json's message
/// (`... at line L column C`), the format pydantic's parser also uses.
pub fn loads(bytes: &[u8]) -> Result<Value, String> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let v = PyJson.deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(v)
}

/// `dict.get(key)` on a JSON object.
pub fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Dict(d) => d.get_str(key),
        _ => None,
    }
}

/// The Python type name used in `TypeError` messages.
pub fn type_name(v: &Value) -> &'static str {
    v.type_name()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_repr_of_json() {
        let v = loads(br#"{"b": 1, "a": [true, null, 1.0, "x'y"], "b": 2}"#).expect("json");
        assert_eq!(v.py_repr(), r#"{'b': 2, 'a': [True, None, 1.0, "x'y"]}"#);
        assert_eq!(
            loads(b"{bad").expect_err("invalid"),
            "key must be a string at line 1 column 2"
        );
        assert_eq!(
            loads(b"").expect_err("empty"),
            "EOF while parsing a value at line 1 column 0"
        );
    }
}
