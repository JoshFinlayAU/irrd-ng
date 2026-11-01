//! The request metadata (`request_meta`): e-mail headers or HTTP client
//! details, reported back in replies and notifications.

use crate::json::PyJson;

/// `request_meta`: a dict in insertion order. Values from e-mail headers
/// are strings or `None`; `/v1/submit/` callers can send any JSON in
/// `X-irrd-metadata`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RequestMeta(pub Vec<(String, PyJson)>);

impl RequestMeta {
    /// `request_meta[key] = value`
    pub fn set(&mut self, key: &str, value: PyJson) {
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some(e) => e.1 = value,
            None => self.0.push((key.to_owned(), value)),
        }
    }

    /// `request_meta[key] = value` for an optional string.
    pub fn set_opt(&mut self, key: &str, value: Option<&str>) {
        self.set(
            key,
            value.map_or(PyJson::Null, |v| PyJson::Str(v.to_owned())),
        );
    }

    /// `request_meta.get(key)` when it is a string.
    pub fn get_str(&self, key: &str) -> Option<String> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| match v {
                PyJson::Str(s) => Some(s.clone()),
                _ => None,
            })
    }

    /// `_request_meta_str()`: `> key: value` for each truthy value.
    pub fn report_str(&self) -> String {
        let lines: Vec<String> = self
            .0
            .iter()
            .filter(|(_, v)| v.truthy())
            .map(|(k, v)| format!("> {k}: {}", v.py_str()))
            .collect();
        if lines.is_empty() {
            String::new()
        } else {
            format!("\n{}\n\n", lines.join("\n"))
        }
    }

    /// The dict as JSON.
    pub fn to_json(&self) -> String {
        PyJson::Dict(self.0.clone()).dumps()
    }

    /// `repr()` of the dict, for logging.
    pub fn py_repr(&self) -> String {
        PyJson::Dict(self.0.clone()).py_repr()
    }
}
