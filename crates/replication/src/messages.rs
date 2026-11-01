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
    format!("replication protocol {active} on the active and {standby} on the standby")
}

pub const LOG_NOT_ENABLED: &str = "the active's replication log is not enabled";

pub const STOPPED: &str = "Replication follower stopped";
