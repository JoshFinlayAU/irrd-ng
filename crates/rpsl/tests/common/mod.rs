//! Shared comparison against v4 oracle output (`parity/oracle/rpsl_oracle.py`).

#![allow(dead_code, unreachable_pub)]

use std::collections::BTreeMap;
use std::fmt::Write as _;

use rpsl::{Keyring, ParseError, ParseOptions, RpslObject, RpslSettings, Value, rpsl_object_from_text};
use serde_json::{Map, Value as Json, json};


fn value_json(v: &Value) -> Json {
    match v {
        Value::Str(s) => json!(s),
        Value::List(l) => json!(l),
    }
}

fn object_json(obj: &RpslObject) -> Json {
    let mut m = Map::new();
    m.insert("class".into(), json!(obj.rpsl_object_class()));
    m.insert(
        "messages".into(),
        Json::Array(
            obj.messages()
                .all()
                .iter()
                .map(|(l, t)| json!([l.as_str(), t]))
                .collect(),
        ),
    );
    if obj.messages().has_errors() {
        return Json::Object(m);
    }
    m.insert("pk".into(), json!(obj.pk()));
    m.insert(
        "source".into(),
        match obj.source() {
            Ok(s) => json!(s),
            Err(e) => json!(format!("EXCEPTION {e}")),
        },
    );
    let mut pd = Map::new();
    for (k, v) in obj.parsed_data() {
        pd.insert((*k).to_owned(), value_json(v));
    }
    m.insert("parsed_data".into(), Json::Object(pd));
    m.insert("rendered".into(), json!(obj.render_rpsl_text()));
    m.insert("ip_first".into(), json!(obj.ip_first.map(|i| i.to_string())));
    m.insert("ip_last".into(), json!(obj.ip_last.map(|i| i.to_string())));
    m.insert("ip_version".into(), json!(obj.ip_version()));
    m.insert("prefix".into(), json!(obj.prefix.map(|i| i.to_string())));
    m.insert("prefix_length".into(), json!(obj.prefix_length));
    m.insert("asn_first".into(), json!(obj.asn_first));
    m.insert("asn_last".into(), json!(obj.asn_last));
    m.insert(
        "referred_strong_objects".into(),
        Json::Array(
            obj.referred_strong_objects()
                .into_iter()
                .map(|(name, classes, data)| json!([name, classes, value_json(data)]))
                .collect(),
        ),
    );
    m.insert(
        "references_strong_inbound".into(),
        json!(obj.references_strong_inbound()),
    );
    Json::Object(m)
}

/// Parse `paragraph` the way the oracle does and render the result in the
/// oracle's JSON shape.
pub fn parse_json(paragraph: &str, strict: bool, settings: &RpslSettings, keyring: &Keyring) -> Json {
    let options = ParseOptions {
        strict,
        default_source: None,
        settings,
        keyring,
    };
    match rpsl_object_from_text(rpsl::text::py_strip(paragraph), &options) {
        Ok(obj) => object_json(&obj),
        Err(ParseError::UnknownClass { class }) => {
            json!({"unknown_class": class, "error": format!("unknown object class: {class}")})
        }
        Err(ParseError::Uncaught(e)) => json!({"exception": e}),
    }
}

/// Per-source comparison tally.
#[derive(Debug, Default)]
pub struct Tally {
    pub paragraphs: usize,
    pub exact: [usize; 2],
    pub by_field: BTreeMap<String, usize>,
    pub examples: Vec<String>,
}

impl Tally {
    pub fn mismatches(&self) -> usize {
        self.by_field.values().sum()
    }
}

/// Compare one oracle row (`{i, paragraph, strict, relaxed}`) against
/// irrd-ng, recording mismatches by field.
pub fn compare_row(
    row: &Json,
    paragraph: &str,
    settings: &RpslSettings,
    keyring: &Keyring,
    tally: &mut Tally,
    max_examples: usize,
) {
    tally.paragraphs += 1;
    // The oracle parses strict first, then relaxed, sharing one keyring.
    for (mode_idx, mode) in ["strict", "relaxed"].iter().enumerate() {
        let expected = &row[*mode];
        let actual = parse_json(paragraph, mode_idx == 0, settings, keyring);
        let exp = expected.as_object().cloned().unwrap_or_default();
        let act = actual.as_object().cloned().unwrap_or_default();
        let mut keys: Vec<&String> = exp.keys().chain(act.keys()).collect();
        keys.sort();
        keys.dedup();
        let mut ok = true;
        for k in keys {
            if exp.get(k) != act.get(k) {
                ok = false;
                *tally.by_field.entry(format!("{mode}.{k}")).or_default() += 1;
                if tally.examples.len() < max_examples {
                    let mut s = String::new();
                    let _ = writeln!(s, "--- #{} {mode}.{k}", row["i"]);
                    let _ = writeln!(s, "paragraph: {:?}", truncate(paragraph, 600));
                    let _ = writeln!(s, "v4:       {}", truncate(&json_str(exp.get(k)), 1500));
                    let _ = writeln!(s, "irrd-ng:  {}", truncate(&json_str(act.get(k)), 1500));
                    tally.examples.push(s);
                }
            }
        }
        if ok {
            tally.exact[mode_idx] += 1;
        }
    }
}

fn json_str(v: Option<&Json>) -> String {
    v.map_or_else(|| "<absent>".to_owned(), |v| v.to_string())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_owned()
    } else {
        s.chars().take(n).collect::<String>() + "..."
    }
}

/// Read a JSONL file into rows.
pub fn read_jsonl(path: &std::path::Path) -> Vec<Json> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
        .collect()
}

/// Compare a raw `.db` file against its oracle rows, checking the paragraph
/// split first. Returns the tally; paragraph split differences are recorded
/// under the `paragraph` field.
pub fn compare_file(db: &[u8], rows: &[Json], max_examples: usize) -> Tally {
    let settings = RpslSettings::default();
    let keyring = Keyring::new();
    let paragraphs = rpsl::split_rpsl_file(db);
    let mut tally = Tally::default();
    if paragraphs.len() != rows.len() {
        *tally.by_field.entry("paragraph-count".into()).or_default() += 1;
        tally.examples.push(format!(
            "paragraph count: v4 {} irrd-ng {}",
            rows.len(),
            paragraphs.len()
        ));
    }
    for (row, para) in rows.iter().zip(&paragraphs) {
        let expected_para = row["paragraph"].as_str().unwrap_or_default();
        if expected_para != para {
            *tally.by_field.entry("paragraph".into()).or_default() += 1;
            if tally.examples.len() < max_examples {
                tally.examples.push(format!(
                    "--- #{} paragraph\nv4:      {expected_para:?}\nirrd-ng: {para:?}",
                    row["i"]
                ));
            }
        }
        compare_row(row, expected_para, &settings, &keyring, &mut tally, max_examples);
    }
    tally
}
