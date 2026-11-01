//! JSON as `ujson.dumps()` (ujson 5.13, v4's defaults) writes it: no
//! spaces, `ensure_ascii` with lower-case `\u` escapes and surrogate pairs,
//! and `escape_forward_slashes`, so `/` becomes `\/`.

use std::fmt::Write as _;

/// A JSON string.
pub fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' => out.push_str("\\/"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) >= 0x80 => {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{u:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A JSON object from `(key, value)` pairs whose values are already
/// encoded, in order.
pub fn write_object(out: &mut String, items: &[(&str, &str)]) {
    out.push('{');
    for (i, (k, v)) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_str(out, k);
        out.push(':');
        out.push_str(v);
    }
    out.push('}');
}

/// An encoded string value.
pub fn string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    write_str(&mut out, s);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded from `ujson.dumps()` in the pinned v4 image.
    #[test]
    fn like_ujson() {
        let input: String = (0u8..0x30)
            .map(char::from)
            .chain("\x7f\u{80}\u{ff}<>&\u{100}\u{ffff}\u{10000}".chars())
            .collect();
        let mut out = String::new();
        write_object(
            &mut out,
            &[("a", &string(&input)), ("n", "4"), ("u", "null")],
        );
        assert_eq!(
            out,
            "{\"a\":\"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\b\\t\\n\\u000b\\f\\r\\u000e\\u000f\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f !\\\"#$%&'()*+,-.\\/\x7f\\u0080\\u00ff<>&\\u0100\\uffff\\ud800\\udc00\",\"n\":4,\"u\":null}"
        );
        let mut out = String::new();
        write_object(
            &mut out,
            &[(
                "object",
                &string("route: 1.2.3.0/24\nr\u{e9}mark: \"x\"\t\u{1}\u{2028} \u{1F600}"),
            )],
        );
        assert_eq!(
            out,
            r#"{"object":"route: 1.2.3.0\/24\nr\u00e9mark: \"x\"\t\u0001\u2028 \ud83d\ude00"}"#
        );
    }
}
