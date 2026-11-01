//! Log messages. v4 has no native replication, so these are irrd-ng's own.

pub fn listening(interface: &str, port: u16) -> String {
    format!("Serving the replication log to standbys on TCP ('{interface}', {port})")
}

pub fn bind_failed(interface: &str, port: u16, e: &std::io::Error) -> String {
    format!("Unable to start the replication server on ('{interface}', {port}): {e}")
}

pub fn standby_connected(peer: &str, from: &str) -> String {
    format!("Standby {peer} connected, streaming {from}")
}

pub fn standby_disconnected(peer: &str, e: &str) -> String {
    format!("Standby {peer} disconnected: {e}")
}

pub fn standby_refused(peer: &str, e: &str) -> String {
    format!("Refused replication connection from {peer}: {e}")
}

pub fn sending_snapshot(peer: &str, seq: u64) -> String {
    format!("Sending a snapshot at log entry {seq} to standby {peer}")
}

pub fn trimmed(n: u64) -> String {
    format!("Removed {n} replication log entries past retention")
}

pub fn log_enabled(id: &str) -> String {
    format!("Replication log enabled, log id {id}")
}

pub const LOG_DISABLED: &str =
    "Replication log disabled: ng_replication.port is not set, existing entries removed";

pub fn following(host: &str, port: u16) -> String {
    format!("Following the active at {host} port {port}")
}

pub fn connected(host: &str, port: u16, from: &str) -> String {
    format!("Connected to the active at {host} port {port}, continuing {from}")
}

pub fn session_failed(host: &str, port: u16, e: &str, retry: u64) -> String {
    format!("Replication from {host} port {port} interrupted: {e}; retrying in {retry}s")
}

pub fn snapshot_loading(id: &str, seq: u64) -> String {
    format!("Loading a snapshot of log {id} at entry {seq} from the active")
}

pub fn snapshot_loaded(rows: u64, secs: f64) -> String {
    format!("Snapshot loaded: {rows} rows in {secs:.1}s")
}

pub const AUTH_FAILED: &str = "authentication failed: check ng_replication.secret on both servers";

pub fn schema_mismatch(active: u32, standby: u32) -> String {
    format!(
        "store schema version {active} on the active and {standby} on the standby: run the same irrd-ng version on both"
    )
}

pub fn protocol_mismatch(active: u32, standby: u32) -> String {
    format!(
        "replication protocol {active} on the active and {standby} on the standby: run the same irrd-ng version on both"
    )
}

/// A connection closed before the handshake because too many are already
/// waiting to prove the secret.
pub const TOO_MANY_PENDING: &str = "too many connections waiting to authenticate; closed without a reply (further refusals logged at debug level for a minute)";

pub const TOO_MANY_PENDING_PEER: &str = "too many connections from this address waiting to authenticate; closed without a reply (further refusals logged at debug level for a minute)";

pub const LOCKED_OUT: &str = "too many failed authentications from this address; closed without a reply (further refusals logged at debug level for a minute)";

pub fn locked_out(ip: &str) -> String {
    format!(
        "{ip} failed replication authentication {} times; refusing its connections for {}s",
        crate::gate::MAX_FAILURES,
        crate::gate::LOCKOUT.as_secs()
    )
}

pub fn spool_failed(path: &str, e: &std::io::Error) -> String {
    format!("Unable to create the snapshot spool {path}: {e}")
}

/// Text the other end sent (an `ERROR` frame), made safe to log: control
/// and format characters, line and paragraph separators included, are
/// escaped, so a peer cannot start a new log line or reorder the text a
/// terminal shows.
pub fn remote_text(raw: &[u8]) -> String {
    use unicode_general_category::{GeneralCategory, get_general_category};
    let text = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let unsafe_char = matches!(
            get_general_category(c),
            GeneralCategory::Control
                | GeneralCategory::Format
                | GeneralCategory::LineSeparator
                | GeneralCategory::ParagraphSeparator
        );
        if unsafe_char {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

pub const LOG_NOT_ENABLED: &str = "the active's replication log is not enabled";

pub const STOPPED: &str = "Replication follower stopped";

pub fn tls_failed(e: &str) -> String {
    format!("TLS handshake failed: {e}")
}

/// Sent to, and logged about, a standby that connects without TLS to an
/// active that requires it.
pub const REQUIRES_TLS: &str = "the active only accepts TLS: set ng_replication.tls_ca or ng_replication.tls_pin on the standby";

pub const TLS_NOT_CONFIGURED: &str = "the standby started a TLS handshake, but ng_replication.tls_certificate and tls_key are not set on this active";

pub const SERVING_PLAINTEXT: &str = "ng_replication.tls_certificate is not set: the replication stream to standbys, including password hashes and API keys, is not encrypted. Use TLS, a private network or a tunnel.";

pub const FOLLOWING_PLAINTEXT: &str = "ng_replication.tls_ca and tls_pin are not set: the replication stream from the active, including password hashes and API keys, is not encrypted. Use TLS, a private network or a tunnel.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_text_escapes_control_characters() {
        assert_eq!(
            remote_text(b"bad\n2026-11-01 INFO forged line\r\x1b[2J"),
            "bad\\u{a}2026-11-01 INFO forged line\\u{d}\\u{1b}[2J"
        );
        assert_eq!(
            remote_text("a\u{202e}b\u{2028}c\u{7f}".as_bytes()),
            "a\\u{202e}b\\u{2028}c\\u{7f}"
        );
        // Ordinary text, non-ASCII letters included, is left alone.
        assert_eq!(remote_text("Zürich: ok".as_bytes()), "Zürich: ok");
        assert_eq!(remote_text(b"\xff"), "\u{fffd}");
    }
}
