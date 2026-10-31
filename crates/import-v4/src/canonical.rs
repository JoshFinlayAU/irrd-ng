//! The canonical JSONL rendering of v4 rows.
//!
//! Byte for byte what `parity/tools/export_v4.py` writes for the same row,
//! so a v4 database and anything that claims to hold the same data can be
//! compared with a plain diff. The rules are in that script's docstring.

use std::io::{self, Write};

use serde_json::Value;

use crate::rows::Cell;

/// Write one row as a JSON object line, keys sorted.
pub fn write_row<W: Write>(out: &mut W, cells: &[(&str, Cell<'_>)]) -> io::Result<()> {
    let mut sorted: Vec<&(&str, Cell<'_>)> = cells.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    out.write_all(b"{")?;
    for (i, (name, cell)) in sorted.into_iter().enumerate() {
        if i > 0 {
            out.write_all(b",")?;
        }
        write_str(out, name)?;
        out.write_all(b":")?;
        write_cell(out, cell)?;
    }
    out.write_all(b"}\n")
}

fn write_cell<W: Write>(out: &mut W, cell: &Cell<'_>) -> io::Result<()> {
    match cell {
        Cell::Null => out.write_all(b"null"),
        Cell::Bool(b) => out.write_all(if *b { b"true" } else { b"false" }),
        Cell::Int(n) => write!(out, "{n}"),
        Cell::Text(s) => write_str(out, s),
        Cell::Uuid(u) => write!(out, "\"{}\"", u.hyphenated()),
        Cell::Timestamp(t) => write!(out, "\"{t}\""),
        Cell::Inet(i) => write!(out, "\"{i}\""),
        Cell::Numeric(n) => write!(out, "\"{n}\""),
        Cell::Enum(label) => write_str(out, label),
        Cell::Json(text) => {
            let value: Value = serde_json::from_str(text)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            write_json(out, &value)
        }
        Cell::Bytes(bytes) => {
            out.write_all(b"\"")?;
            for b in *bytes {
                write!(out, "{b:02x}")?;
            }
            out.write_all(b"\"")
        }
        Cell::TextArray(items) => {
            out.write_all(b"[")?;
            for (i, s) in items.iter().enumerate() {
                if i > 0 {
                    out.write_all(b",")?;
                }
                write_str(out, s)?;
            }
            out.write_all(b"]")
        }
    }
}

/// JSON with object keys sorted at every level, whatever map type
/// serde_json was built with.
pub fn write_json<W: Write>(out: &mut W, value: &Value) -> io::Result<()> {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.write_all(b"{")?;
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.write_all(b",")?;
                }
                write_str(out, k)?;
                out.write_all(b":")?;
                write_json(out, &map[k])?;
            }
            out.write_all(b"}")
        }
        Value::Array(items) => {
            out.write_all(b"[")?;
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.write_all(b",")?;
                }
                write_json(out, v)?;
            }
            out.write_all(b"]")
        }
        Value::String(s) => write_str(out, s),
        other => serde_json::to_writer(&mut *out, other).map_err(io::Error::other),
    }
}

/// A JSON string as Python's `json.dumps(ensure_ascii=False)` writes it:
/// only `"`, `\` and control characters escaped, the short forms where JSON
/// has them, `\u00xx` (lowercase) otherwise. serde_json does the same.
fn write_str<W: Write>(out: &mut W, s: &str) -> io::Result<()> {
    serde_json::to_writer(out, s).map_err(io::Error::other)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::Timestamp;

    fn render(cells: &[(&str, Cell<'_>)]) -> String {
        let mut buf = Vec::new();
        write_row(&mut buf, cells).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn matches_python_json_dumps() {
        // json.dumps({...}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        let line = render(&[
            ("z", Cell::Text("tab\there \"q\" \\ ünï \u{1} \u{7f}")),
            ("a", Cell::Null),
            (
                "m",
                Cell::Json(r#"{"b": [1, {"y": 2, "x": "é"}], "a": null}"#),
            ),
            ("t", Cell::Timestamp(Timestamp(0))),
            ("bytes", Cell::Bytes(&[0, 0xff])),
        ]);
        assert_eq!(
            line,
            "{\"a\":null,\"bytes\":\"00ff\",\"m\":{\"a\":null,\"b\":[1,{\"x\":\"é\",\"y\":2}]},\
             \"t\":\"1970-01-01T00:00:00.000000Z\",\"z\":\"tab\\there \\\"q\\\" \\\\ ünï \\u0001 \u{7f}\"}\n"
        );
    }
}
