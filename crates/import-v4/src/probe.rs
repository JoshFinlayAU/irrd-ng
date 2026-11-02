//! A quick, read-only look at the size of a v4 database, for
//! `irrd-ng migrate-check` to estimate the store an import will build.

use std::time::Duration;

use postgres::{Client, IsolationLevel};

use crate::ImportError;

/// How large a v4 database is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceSize {
    /// `pg_database_size(current_database())`, in bytes.
    pub database_bytes: Option<u64>,
    /// Rows in `rpsl_objects`.
    pub rpsl_objects: u64,
    /// Rows in `rpsl_database_journal`.
    pub journal: u64,
    /// Rows in `roa_object`.
    pub roas: u64,
    /// The counts are the planner's estimates (`pg_class.reltuples`)
    /// because counting took longer than the statement timeout.
    pub approximate: bool,
}

impl SourceSize {
    /// The rows an import turns into store records that scale with size.
    pub fn rows(&self) -> u64 {
        self.rpsl_objects + self.journal + self.roas
    }
}

const TABLES: [&str; 3] = ["rpsl_objects", "rpsl_database_journal", "roa_object"];

/// Measure the database at `dsn`, in a read-only transaction, giving up on
/// the connection after `connect_timeout`. Exact row counts are tried
/// first, under `statement_timeout`; when that runs out, the planner's
/// estimates are used instead.
pub fn probe_size(
    dsn: &str,
    connect_timeout: Duration,
    statement_timeout: Duration,
) -> Result<SourceSize, ImportError> {
    let mut client = crate::connect_as(dsn, "irrd-ng migrate-check", Some(connect_timeout))?;
    crate::check_source(&mut client)?;
    match measure(&mut client, Some(statement_timeout)) {
        Ok(size) => Ok(size),
        Err(_) => measure(&mut client, None),
    }
}

/// Exact counts with `Some(timeout)`, estimates with `None`.
fn measure(client: &mut Client, exact: Option<Duration>) -> Result<SourceSize, ImportError> {
    let mut tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .map_err(ImportError::Connect)?;
    let err = |table| move |source| ImportError::Query { table, source };
    if let Some(t) = exact {
        tx.batch_execute(&format!(
            "SET LOCAL statement_timeout = {}",
            t.as_millis().max(1)
        ))
        .map_err(err("statement_timeout"))?;
    }
    let database_bytes = tx
        .query_one("SELECT pg_database_size(current_database())", &[])
        .and_then(|r| r.try_get::<_, i64>(0))
        .ok()
        .and_then(|n| u64::try_from(n).ok());
    let mut counts = [0u64; 3];
    for (n, table) in counts.iter_mut().zip(TABLES) {
        let sql = if exact.is_some() {
            format!("SELECT count(*) FROM {table}")
        } else {
            format!(
                "SELECT greatest(reltuples, 0)::bigint FROM pg_class WHERE oid = '{table}'::regclass"
            )
        };
        let v: i64 = tx
            .query_one(&sql, &[])
            .and_then(|r| r.try_get(0))
            .map_err(err(table))?;
        *n = u64::try_from(v).unwrap_or(0);
    }
    tx.rollback().map_err(ImportError::Connect)?;
    Ok(SourceSize {
        database_bytes,
        rpsl_objects: counts[0],
        journal: counts[1],
        roas: counts[2],
        approximate: exact.is_none(),
    })
}
