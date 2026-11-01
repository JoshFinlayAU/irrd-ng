//! The JSON parse errors pydantic 2.12 (jiter) reports for an invalid
//! subscription request, for the common cases.

/// The jiter error text for `data`, with its line and column.
pub(crate) fn json_error(data: &str) -> String {
    let chars: Vec<char> = data.chars().collect();
    let pos_of = |i: usize| -> (usize, usize) {
        let mut line = 1;
        let mut col = 0;
        for c in chars.iter().take(i) {
            if *c == '\n' {
                line += 1;
                col = 0;
            } else {
                col += 1;
            }
        }
        (line, col)
    };
    let mut i = 0;
    while i < chars.len() && matches!(chars[i], ' ' | '\t' | '\n' | '\r') {
        i += 1;
    }
    if i >= chars.len() {
        let (l, c) = pos_of(i);
        return format!("EOF while parsing a value at line {l} column {c}");
    }
    let c = chars[i];
    if c.is_ascii_alphabetic() {
        // An identifier other than true/false/null: jiter reads one
        // character and fails on the next.
        let (l, col) = pos_of(i + 2);
        return format!("expected ident at line {l} column {col}");
    }
    if matches!(c, '{' | '[' | '"' | '-' | '0'..='9') {
        let (l, col) = pos_of(chars.len());
        return format!("EOF while parsing a value at line {l} column {col}");
    }
    let (l, col) = pos_of(i + 1);
    format!("expected value at line {l} column {col}")
}
