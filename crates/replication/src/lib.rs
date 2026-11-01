//! Native standby replication (PLAN.md D2).
//!
//! v4 runs a standby as a PostgreSQL streaming replica. irrd-ng has no
//! PostgreSQL, so it replicates its own store: the active keeps a
//! replication log of every committed change to every table
//! ([`store::replog`]) and serves it over an authenticated TCP stream,
//! optionally inside TLS ([`server`], [`tls`]); a standby follows that stream ([`follower`]) and applies
//! each transaction in order, so its store holds the same rows as the
//! active's. A standby that is new, or too far behind for the kept log,
//! first loads a snapshot of every table.
//!
//! The standby otherwise runs with `readonly_standby: true` and keeps v4's
//! meaning of it: it never writes on its own, and replication is the one
//! writer.

#![deny(unsafe_code)]

pub mod follower;
#[doc(hidden)]
pub mod fuzzing;
pub mod messages;
pub mod protocol;
pub mod server;
pub mod tls;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Log target for replication messages (irrd-ng's own).
pub const LOG_TARGET: &str = "irrd_ng.replication";

/// Why a replication session ended.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Network or file I/O.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// The other end broke the protocol, or failed authentication.
    #[error("{0}")]
    Protocol(String),
    /// The other end reported an error.
    #[error("{0}")]
    Remote(String),
    /// The store refused.
    #[error("{0}")]
    Store(#[from] store::StoreError),
    /// Waiting for the other end took too long.
    #[error("timed out")]
    Timeout,
}

/// The active: where to listen and the shared secret.
#[derive(Debug, Clone)]
pub struct ServerSettings {
    /// The address to listen on.
    pub interface: String,
    /// The TCP port.
    pub port: u16,
    /// The shared secret.
    pub secret: Vec<u8>,
    /// How long log entries are kept for standbys that were away.
    pub retention: Duration,
    /// How often an idle stream carries a heartbeat.
    pub heartbeat: Duration,
    /// TLS: when set, standbys must connect with TLS.
    pub tls: Option<Arc<rustls::ServerConfig>>,
}

impl ServerSettings {
    /// Defaults for everything but the address and secret.
    pub fn new(interface: impl Into<String>, port: u16, secret: impl Into<Vec<u8>>) -> Self {
        ServerSettings {
            interface: interface.into(),
            port,
            secret: secret.into(),
            retention: Duration::from_secs(24 * 3600),
            heartbeat: Duration::from_secs(5),
            tls: None,
        }
    }
}

/// The standby: where the active is and the shared secret.
#[derive(Debug, Clone)]
pub struct FollowerSettings {
    /// The active's host name or address.
    pub host: String,
    /// The active's replication port.
    pub port: u16,
    /// The shared secret.
    pub secret: Vec<u8>,
    /// Where a snapshot is spooled before it is applied.
    pub spool_dir: PathBuf,
    /// A stream silent for this long is dropped and reconnected.
    pub idle_timeout: Duration,
    /// The longest wait between reconnection attempts.
    pub max_backoff: Duration,
    /// TLS: when set, the standby only connects with TLS and checks the
    /// active's certificate.
    pub tls: Option<tls::ClientTls>,
}

impl FollowerSettings {
    /// Defaults for everything but the address, secret and spool place.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        secret: impl Into<Vec<u8>>,
        spool_dir: impl Into<PathBuf>,
    ) -> Self {
        FollowerSettings {
            host: host.into(),
            port,
            secret: secret.into(),
            spool_dir: spool_dir.into(),
            idle_timeout: Duration::from_secs(30),
            max_backoff: Duration::from_secs(30),
            tls: None,
        }
    }
}
