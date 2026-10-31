//! JSON text as `ujson.dumps(..., indent=4)` writes it: `": "` after keys,
//! four spaces per level, non-ASCII and control characters escaped as
//! `\uXXXX`, and `/` escaped as `\/`.

use std::fmt::Write as _;

pub(crate) fn newline(out: &mut String, depth: usize) {
    out.push('\n');
    for _ in 0..depth {
        out.push_str("    ");
    }
}

pub(crate) fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' => out.push_str("\\/"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) >= 0x80 => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub(crate) fn write_float(out: &mut String, f: f64) {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e16 {
        let _ = write!(out, "{f:.1}");
    } else {
        let _ = write!(out, "{f}");
    }
}

pub(crate) fn write_list<I, T>(
    out: &mut String,
    depth: usize,
    items: I,
    mut each: impl FnMut(&mut String, T, usize),
) where
    I: Iterator<Item = T>,
{
    let mut any = false;
    out.push('[');
    for (i, item) in items.enumerate() {
        any = true;
        if i > 0 {
            out.push(',');
        }
        newline(out, depth + 1);
        each(out, item, depth + 1);
    }
    if any {
        newline(out, depth);
    }
    out.push(']');
}

/// A JSON object written key by key.
pub(crate) struct Object<'a> {
    out: &'a mut String,
    depth: usize,
    any: bool,
}

impl<'a> Object<'a> {
    pub(crate) fn new(out: &'a mut String, depth: usize) -> Self {
        out.push('{');
        Object {
            out,
            depth,
            any: false,
        }
    }

    pub(crate) fn key(&mut self, k: &str) -> &mut String {
        if self.any {
            self.out.push(',');
        }
        self.any = true;
        newline(self.out, self.depth + 1);
        write_str(self.out, k);
        self.out.push_str(": ");
        self.out
    }

    pub(crate) fn depth(&self) -> usize {
        self.depth + 1
    }

    pub(crate) fn finish(self) {
        if self.any {
            newline(self.out, self.depth);
        }
        self.out.push('}');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_escape_like_ujson() {
        let mut s = String::new();
        write_str(&mut s, "a/b é\u{2028}\u{1}\"");
        assert_eq!(s, "\"a\\/b \\u00e9\\u2028\\u0001\\\"\"");
        let mut s = String::new();
        write_str(&mut s, "\u{1F600}");
        assert_eq!(s, "\"\\ud83d\\ude00\"");
    }

    #[test]
    fn nested_layout_like_ujson() {
        let mut s = String::new();
        let mut o = Object::new(&mut s, 0);
        o.key("a").push_str("[]");
        let d = o.depth();
        let out = o.key("c");
        write_list(out, d, ["x", "y"].into_iter(), |o, v, _| write_str(o, v));
        o.key("e").push_str("null");
        o.finish();
        assert_eq!(
            s,
            "{\n    \"a\": [],\n    \"c\": [\n        \"x\",\n        \"y\"\n    ],\n    \"e\": null\n}"
        );
    }
}
