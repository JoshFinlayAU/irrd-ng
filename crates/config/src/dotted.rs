//! v4's vendored `DottedDict` (`irrd/vendor/dotted/collection.py`).
//!
//! v4 wraps the `irrd` mapping in a `DottedDict` before checking it, and that
//! has visible effects: construction rejects non-string and dotted keys
//! (crashing v4), and `config.get("a.b.c")` walks nested mappings, returning
//! the default when a level is missing or is a scalar but raising when a
//! level is a list.

use crate::python::{Dict, PyException, Value};

/// Whether the key has a dot not preceded by a backslash.
pub(crate) fn is_dotted_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    bytes
        .iter()
        .enumerate()
        .any(|(i, b)| *b == b'.' && (i == 0 || bytes[i - 1] != b'\\'))
}

/// `split_key(key, 1)`: split at the first unescaped dot.
pub(crate) fn split_first(key: &str) -> Option<(&str, &str)> {
    let bytes = key.as_bytes();
    let pos = bytes
        .iter()
        .enumerate()
        .position(|(i, b)| *b == b'.' && (i == 0 || bytes[i - 1] != b'\\'))?;
    Some((&key[..pos], &key[pos + 1..]))
}

/// `DottedDict(initial)` for the value of the `irrd` root key. Returns the
/// mapping v4 would go on to check, or the exception it would crash with.
pub(crate) fn dotted_dict_from(initial: &Value) -> Result<Dict, PyException> {
    let dict = match initial {
        Value::None => Dict::new(),
        other => dict_constructor(other)?,
    };
    validate_initial_dict(&dict)?;
    Ok(dict)
}

/// Python's `dict(x)`.
fn dict_constructor(value: &Value) -> Result<Dict, PyException> {
    if let Value::Dict(d) = value {
        return Ok(d.clone());
    }
    let elements = match value {
        Value::List(items) | Value::Tuple(items) | Value::Set(items) => items.clone(),
        Value::Str(_) | Value::Bytes(_) => value.py_iter()?,
        other => return Err(PyException::not_iterable(other)),
    };
    let mut out = Dict::new();
    for (i, element) in elements.iter().enumerate() {
        let pair = match element {
            Value::List(items) | Value::Tuple(items) | Value::Set(items) => items.clone(),
            Value::Str(_) | Value::Dict(_) => element.py_iter()?,
            Value::Bytes(_) => element.py_iter()?,
            _ => {
                return Err(PyException::type_error(format!(
                    "cannot convert dictionary update sequence element #{i} to a sequence"
                )));
            }
        };
        if pair.len() != 2 {
            return Err(PyException::value_error(format!(
                "dictionary update sequence element #{i} has length {}; 2 is required",
                pair.len()
            )));
        }
        if !pair[0].is_hashable() {
            return Err(PyException::unhashable(&pair[0]));
        }
        out.insert(pair[0].clone(), pair[1].clone());
    }
    Ok(out)
}

fn validate_initial_dict(dict: &Dict) -> Result<(), PyException> {
    for (key, item) in dict.iter() {
        match key {
            Value::Str(k) => {
                if is_dotted_key(k) {
                    return Err(PyException::value_error(format!(
                        "{k} is not a valid key inside a DottedCollection!"
                    )));
                }
            }
            Value::Bytes(_) => {
                return Err(PyException::type_error(
                    "cannot use a string pattern on a bytes-like object",
                ));
            }
            other => {
                return Err(PyException::type_error(format!(
                    "expected string or bytes-like object, got '{}'",
                    other.type_name()
                )));
            }
        }
        validate_initial(item)?;
    }
    Ok(())
}

fn validate_initial(value: &Value) -> Result<(), PyException> {
    match value {
        Value::List(items) => items.iter().try_for_each(validate_initial),
        Value::Dict(d) => validate_initial_dict(d),
        _ => Ok(()),
    }
}

/// `MutableMapping.get(key)` on a `DottedDict`: `Ok(None)` where v4 gets
/// the default (a `KeyError` was raised and caught).
pub(crate) fn get<'a>(dict: &'a Dict, key: &str) -> Result<Option<&'a Value>, PyException> {
    match getitem_dict(dict, key) {
        Lookup::Found(v) => Ok(Some(v)),
        Lookup::KeyError => Ok(None),
        Lookup::Raise(e) => Err(e),
    }
}

enum Lookup<'a> {
    Found(&'a Value),
    KeyError,
    Raise(PyException),
}

fn getitem_dict<'a>(dict: &'a Dict, key: &str) -> Lookup<'a> {
    let Some((my_key, alt_key)) = split_first(key) else {
        return match dict.get_str(key) {
            Some(v) => Lookup::Found(v),
            None => Lookup::KeyError,
        };
    };
    let Some(target) = dict.get_str(my_key) else {
        return Lookup::KeyError;
    };
    match target {
        Value::Dict(d) => getitem_dict(d, alt_key),
        Value::List(items) => getitem_list(items, alt_key),
        _ => Lookup::KeyError,
    }
}

fn getitem_list<'a>(items: &'a [Value], index: &str) -> Lookup<'a> {
    let out_of_range = || Lookup::Raise(PyException::new("IndexError", "list index out of range"));
    if !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()) {
        return match index.parse::<usize>().ok().and_then(|i| items.get(i)) {
            Some(v) => Lookup::Found(v),
            None => out_of_range(),
        };
    }
    if let Some((my_index, alt_index)) = split_first(index) {
        let i = match crate::python::int_from_str(my_index, 10) {
            Ok(i) => i,
            Err(e) => return Lookup::Raise(e),
        };
        let target = usize::try_from(i).ok().and_then(|i| items.get(i));
        let Some(target) = target else {
            return out_of_range();
        };
        return match target {
            Value::Dict(d) => getitem_dict(d, alt_index),
            Value::List(l) => getitem_list(l, alt_index),
            other => Lookup::Raise(PyException::new(
                "IndexError",
                format!(
                    "cannot get \"{alt_index}\" in \"{my_index}\" ({})",
                    other.py_repr()
                ),
            )),
        };
    }
    Lookup::Raise(PyException::new(
        "IndexError",
        format!(
            "cannot get {index} in {}",
            Value::List(items.to_vec()).py_repr()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(pairs: Vec<(&str, Value)>) -> Value {
        let mut dict = Dict::new();
        for (k, v) in pairs {
            dict.insert(Value::str(k), v);
        }
        Value::Dict(dict)
    }

    #[test]
    fn dotted_lookup() {
        let root = d(vec![
            ("a", d(vec![("b", Value::int(1))])),
            ("s", Value::str("x")),
            ("l", Value::List(vec![Value::int(5)])),
        ]);
        let Value::Dict(root) = root else { panic!() };
        assert!(matches!(get(&root, "a.b"), Ok(Some(Value::Int(_)))));
        assert!(matches!(get(&root, "a.c"), Ok(None)));
        assert!(matches!(get(&root, "s.x"), Ok(None)));
        assert!(matches!(get(&root, "missing.x"), Ok(None)));
        assert!(get(&root, "l.x").is_err());
        assert!(matches!(get(&root, "l.0"), Ok(Some(_))));
        assert!(get(&root, "l.1").is_err());
    }

    #[test]
    fn construction_rejects_bad_keys() {
        let mut inner = Dict::new();
        inner.insert(Value::int(1), Value::None);
        let root = d(vec![("x", Value::Dict(inner))]);
        assert_eq!(
            dotted_dict_from(&root).map_err(|e| e.to_string()).err(),
            Some("TypeError: expected string or bytes-like object, got 'int'".to_owned())
        );
        let root = d(vec![("a.b", Value::None)]);
        assert_eq!(
            dotted_dict_from(&root).map_err(|e| e.to_string()).err(),
            Some("ValueError: a.b is not a valid key inside a DottedCollection!".to_owned())
        );
        let root = d(vec![("a\\.b", Value::None)]);
        assert!(dotted_dict_from(&root).is_ok());
        assert!(dotted_dict_from(&Value::None).is_ok_and(|d| d.is_empty()));
    }
}
