//! `limits.parse()` from the `limits` 5.6 library, which v4 uses to check
//! `auth.webui_auth_failure_rate_limit` (only whether it raises matters).

use std::sync::LazyLock;

use regex::Regex;

/// Python's `\s` for str patterns: every character `str.isspace()` accepts.
const WS: &str = r"[\t\n\x0B\x0C\r\x1C-\x1F \x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]";

fn single() -> String {
    format!(r"{WS}*([0-9]+){WS}*(/|{WS}*per{WS}*){WS}*([0-9]+)?{WS}*([a-z]+){WS}*")
}

#[allow(clippy::expect_used)]
static EXPR: LazyLock<Regex> = LazyLock::new(|| {
    let s = single();
    // `$` in Python also matches before a final newline.
    Regex::new(&format!(r"(?i)\A{s}(?::?[,;|]{s})*\n?\z")).expect("static rate limit pattern")
});

#[allow(clippy::expect_used)]
static SINGLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"(?i)\A{}", single())).expect("static pattern"));

const GRANULARITIES: &[&str] = &["day", "month", "year", "hour", "minute", "second"];

/// Whether `limits.parse(text)` succeeds.
pub(crate) fn parses(text: &str) -> bool {
    if !EXPR.is_match(text) {
        return false;
    }
    for part in text.split([',', ';', '|']) {
        if let Some(caps) = SINGLE.captures(part) {
            let granularity = caps.get(4).map_or("", |m| m.as_str()).to_lowercase();
            let known = GRANULARITIES
                .iter()
                .any(|g| granularity == *g || granularity == format!("{g}s"));
            if !known {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::parses;

    #[test]
    fn matches_limits() {
        for ok in [
            "30/hour",
            "1 per second",
            "5/minute; 100/day",
            "10 per 2 hours",
            "1/HOUR",
        ] {
            assert!(parses(ok), "{ok}");
        }
        for bad in ["invalid", "30/fortnight", "/hour", "30", ""] {
            assert!(!parses(bad), "{bad}");
        }
    }
}
