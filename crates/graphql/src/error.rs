//! `GraphQLError` and its `formatted` JSON shape, and graphql-core's
//! printer for the value and type literals that appear in messages.

use crate::ast::{Type, ValueNode};
use crate::value::Value;

/// A step in a response path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSeg {
    /// A response key.
    Key(String),
    /// A list index.
    Index(usize),
}

/// A `GraphQLError`.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphQLError {
    pub message: String,
    /// Character offsets of the nodes (or positions) it refers to.
    pub positions: Vec<usize>,
    pub path: Option<Vec<PathSeg>>,
    /// Raised from a non-GraphQL exception (`original_error` is not a
    /// `GraphQLError`): IRRd's formatter hides its message.
    pub internal: bool,
    /// `extensions`, when not empty.
    pub extensions: Option<Value>,
}

impl GraphQLError {
    /// An error at these positions.
    pub fn new(message: impl Into<String>, positions: Vec<usize>) -> Self {
        GraphQLError {
            message: message.into(),
            positions,
            path: None,
            internal: false,
            extensions: None,
        }
    }

    /// An error without location.
    pub fn plain(message: impl Into<String>) -> Self {
        GraphQLError::new(message, Vec::new())
    }

    /// IRRd's `error_formatter` applied to `error.formatted`.
    pub fn formatted(&self, body: &[char]) -> Value {
        let mut o: Vec<(String, Value)> = Vec::new();
        let message = if self.internal {
            "Internal server error".to_owned()
        } else if self.message.is_empty() {
            "An unknown error occurred.".to_owned()
        } else {
            self.message.clone()
        };
        o.push(("message".into(), Value::Str(message)));
        if !self.positions.is_empty() {
            let locs = self
                .positions
                .iter()
                .map(|p| {
                    let (line, column) = crate::parser::location(body, *p);
                    Value::Object(vec![
                        ("line".into(), Value::Int(line as i128)),
                        ("column".into(), Value::Int(column as i128)),
                    ])
                })
                .collect();
            o.push(("locations".into(), Value::List(locs)));
        }
        if let Some(path) = &self.path {
            o.push((
                "path".into(),
                Value::List(
                    path.iter()
                        .map(|s| match s {
                            PathSeg::Key(k) => Value::Str(k.clone()),
                            PathSeg::Index(i) => Value::Int(*i as i128),
                        })
                        .collect(),
                ),
            ));
        }
        if let Some(e) = &self.extensions {
            o.push(("extensions".into(), e.clone()));
        }
        Value::Object(o)
    }

    /// `str(error)`: the message and, for each position, the source
    /// location as `print_location()` shows it.
    pub fn to_str(&self, body: &[char]) -> String {
        let mut out = self.message.clone();
        for p in &self.positions {
            out.push_str("\n\n");
            out.push_str(&print_source_location(body, crate::parser::location(body, *p)));
        }
        out
    }
}

/// `print_source_location()` for the source named `GraphQL request`.
pub fn print_source_location(body: &[char], (line, column): (usize, usize)) -> String {
    let text: String = body.iter().collect();
    // The lines here are split on \r\n, \n and \r only.
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\r' => {
                if chars.get(i + 1) == Some(&'\n') {
                    i += 1;
                }
                lines.push(std::mem::take(&mut cur));
            }
            '\n' => lines.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
        i += 1;
    }
    lines.push(cur);
    let line_index = line - 1;
    let location_str = format!("GraphQL request:{line}:{column}\n");
    let location_line: Vec<char> = lines
        .get(line_index)
        .map(|l| l.chars().collect())
        .unwrap_or_default();
    let rjust = |s: &str, w: usize| -> String {
        let n = s.chars().count();
        if n >= w {
            s.to_owned()
        } else {
            format!("{}{s}", " ".repeat(w - n))
        }
    };
    let prefixed = |rows: Vec<(String, Option<String>)>| -> String {
        let existing: Vec<(String, String)> = rows
            .into_iter()
            .filter_map(|(p, l)| l.map(|l| (p, l)))
            .collect();
        let pad = existing.iter().map(|(p, _)| p.chars().count()).max().unwrap_or(0);
        existing
            .iter()
            .map(|(p, l)| {
                let mut s = rjust(p, pad);
                if !l.is_empty() {
                    s.push(' ');
                    s.push_str(l);
                }
                s
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    if location_line.len() > 120 {
        let (sub_index, sub_col) = (column / 80, column % 80);
        let sub_lines: Vec<String> = location_line
            .chunks(80)
            .map(|c| c.iter().collect())
            .collect();
        let mut rows = vec![(format!("{line} |"), Some(sub_lines[0].clone()))];
        for sl in sub_lines.iter().take(sub_index + 1).skip(1) {
            rows.push(("|".to_owned(), Some(sl.clone())));
        }
        rows.push(("|".to_owned(), Some(rjust("^", sub_col))));
        rows.push((
            "|".to_owned(),
            if sub_index + 1 < sub_lines.len() {
                Some(sub_lines[sub_index + 1].clone())
            } else {
                None
            },
        ));
        return location_str + &prefixed(rows);
    }
    let rows = vec![
        (
            format!("{} |", line as i64 - 1),
            if line_index > 0 {
                lines.get(line_index - 1).cloned()
            } else {
                None
            },
        ),
        (format!("{line} |"), Some(location_line.iter().collect())),
        ("|".to_owned(), Some(rjust("^", column))),
        (
            format!("{} |", line + 1),
            if line_index + 1 < lines.len() {
                lines.get(line_index + 1).cloned()
            } else {
                None
            },
        ),
    ];
    location_str + &prefixed(rows)
}

// ---- printer ----

/// `print_string()`
pub fn print_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        let n = c as u32;
        match c {
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ if n < 0x20 || (0x7f..0xa0).contains(&n) => {
                out.push_str(&format!("\\u{n:04X}"));
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `print_block_string()`
fn print_block_string(value: &str) -> String {
    let escaped = value.replace("\"\"\"", "\\\"\"\"");
    let lines = py_splitlines(&escaped);
    let lines = if lines.is_empty() {
        vec![String::new()]
    } else {
        lines
    };
    let is_single_line = lines.len() == 1;
    let force_leading_new_line = lines.len() > 1
        && lines[1..]
            .iter()
            .all(|l| l.is_empty() || l.starts_with([' ', '\t']));
    let has_trailing_triple_quotes = escaped.ends_with("\\\"\"\"");
    let has_trailing_quote = value.ends_with('"') && !has_trailing_triple_quotes;
    let has_trailing_slash = value.ends_with('\\');
    let force_trailing_new_line = has_trailing_quote || has_trailing_slash;
    let print_as_multiple_lines = !is_single_line
        || value.chars().count() > 70
        || force_trailing_new_line
        || force_leading_new_line
        || has_trailing_triple_quotes;
    let skip_leading_new_line = is_single_line && value.starts_with([' ', '\t']);
    let before = if (print_as_multiple_lines && !skip_leading_new_line) || force_leading_new_line {
        "\n"
    } else {
        ""
    };
    let after = if print_as_multiple_lines || force_trailing_new_line {
        "\n"
    } else {
        ""
    };
    format!("\"\"\"{before}{escaped}{after}\"\"\"")
}

/// `str.splitlines()`
pub fn py_splitlines(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if matches!(
            c,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        ) {
            if c == '\r' && chars.get(i + 1) == Some(&'\n') {
                i += 1;
            }
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
        i += 1;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn indent(s: &str) -> String {
    if s.is_empty() {
        String::new()
    } else {
        format!("  {}", s.replace('\n', "\n  "))
    }
}

/// `print_ast()` for a value literal.
pub fn print_value(v: &ValueNode) -> String {
    match v {
        ValueNode::Variable(var) => format!("${}", var.name.value),
        ValueNode::Int(_, s) | ValueNode::Float(_, s) | ValueNode::Enum(_, s) => s.clone(),
        ValueNode::String(_, s, block) => {
            if *block {
                print_block_string(s)
            } else {
                print_string(s)
            }
        }
        ValueNode::Boolean(_, b) => if *b { "true" } else { "false" }.to_owned(),
        ValueNode::Null(_) => "null".to_owned(),
        ValueNode::List(_, items) => {
            let parts: Vec<String> = items.iter().map(print_value).collect();
            let line = format!("[{}]", parts.join(", "));
            if line.chars().count() > 80 {
                format!("[\n{}\n]", indent(&parts.join("\n")))
            } else {
                line
            }
        }
        ValueNode::Object(_, fields) => {
            let parts: Vec<String> = fields
                .iter()
                .map(|f| format!("{}: {}", f.name.value, print_value(&f.value)))
                .collect();
            let line = format!("{{ {} }}", parts.join(", "));
            if line.chars().count() > 80 {
                let inner = indent(&parts.join("\n"));
                if inner.is_empty() {
                    String::new()
                } else {
                    format!("{{\n{inner}\n}}")
                }
            } else {
                line
            }
        }
    }
}

/// `print_ast()` for a type reference.
pub fn print_type(t: &Type) -> String {
    match t {
        Type::Named(n) => n.name.value.clone(),
        Type::List(_, i) => format!("[{}]", print_type(i)),
        Type::NonNull(_, i) => format!("{}!", print_type(i)),
    }
}
