//! User-facing strings, copied verbatim from IRRd v4 at the pinned baseline
//! (`irrd/utils/email.py`) and from the Python exceptions it reports.

/// `logger.error(f"Not sending e-mail {subject!r}: {recipient!r} is not a single valid recipient")`
pub fn bad_recipient(subject: &str, recipient: &str) -> String {
    format!(
        "Not sending e-mail {}: {} is not a single valid recipient",
        py_repr(subject),
        py_repr(recipient)
    )
}

/// `logger.debug(f"Sending email to {recipient}, subject {subject}")`
pub fn sending(recipient: &str, subject: &str) -> String {
    format!("Sending email to {recipient}, subject {subject}")
}

/// `OSError("nonnumeric port")` from `smtplib.SMTP._get_socket`.
pub const NONNUMERIC_PORT: &str = "nonnumeric port";

/// `socket.gaierror` for an unknown name.
pub const GAI_NONAME: &str = "[Errno -2] Name or service not known";

/// `socket.gaierror` text for a failed lookup.
pub fn gaierror(e: &std::io::Error) -> String {
    let _ = e;
    GAI_NONAME.to_owned()
}

/// Python's `repr()` of a str, for the common cases (quotes and escapes).
pub fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}
