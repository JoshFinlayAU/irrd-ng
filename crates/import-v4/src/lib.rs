//! One-shot, read-only migration from an IRRd 4.5 PostgreSQL database.
//!
//! [`import`] opens one `REPEATABLE READ`, `READ ONLY` transaction on the
//! source, so every table is read from the same snapshot and nothing can be
//! written, checks that the schema is v4.5's alembic head, then streams each
//! table through a server-side portal in fixed-size batches. Memory stays
//! bounded by the batch size however large the database is. Reading and
//! writing overlap: a reader thread decodes the next batch while the
//! [`Sink`] stores the previous one.
//!
//! Every column is carried, v4's UUID primary keys and timestamps included,
//! and NRTM serials are passed through untouched, so mirrors carry on
//! without a reload. Whether a re-run upserts or duplicates is the sink's
//! contract: the store sink keys every table on v4's natural or primary key.

use std::sync::mpsc;
use std::time::Instant;

use postgres::{Client, IsolationLevel, NoTls, Transaction};
use tracing::info;

mod dsn;
pub mod messages;
pub mod rows;
pub mod types;

pub use rows::Batch;
use rows::{
    AuthApiToken, AuthMntner, AuthPermission, AuthUser, AuthWebauthn, ChangeLog, DatabaseStatus,
    JournalEntry, ProtectedName, Roa, RpslObject, Setting, SuspendedObject, V4Table,
};

/// Rows per fetch from the source.
pub const DEFAULT_BATCH_ROWS: usize = 5000;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("{0}")]
    Dsn(String),
    #[error("{0}")]
    Tls(String),
    #[error("{0}")]
    Connect(#[source] postgres::Error),
    #[error("{}", messages::no_schema())]
    NoSchema,
    #[error("{}", messages::wrong_schema(.0))]
    WrongSchema(String),
    #[error("{}: {source}", messages::query_failed(.table))]
    Query {
        table: &'static str,
        #[source]
        source: postgres::Error,
    },
    #[error("{}", messages::aborted())]
    Aborted,
    #[error("{}: {source}", messages::sink_failed(.table))]
    Sink {
        table: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// Where imported rows go. The store implements this; tests collect.
pub trait Sink {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Called once, after the schema check and before the first batch.
    fn begin(&mut self, _schema_revision: &str) -> Result<(), Self::Error> {
        Ok(())
    }

    fn write(&mut self, batch: Batch) -> Result<(), Self::Error>;

    /// Called once after the last batch; commit here.
    fn finish(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub batch_rows: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            batch_rows: DEFAULT_BATCH_ROWS,
        }
    }
}

/// Rows read per table, in import order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub schema_revision: String,
    pub tables: Vec<(&'static str, u64)>,
}

impl Stats {
    pub fn total(&self) -> u64 {
        self.tables.iter().map(|(_, n)| n).sum()
    }
}

/// Connect to the source database. `dsn` is a libpq URL or key=value string,
/// or v4's own `database_url`.
pub fn connect(dsn: &str) -> Result<Client, ImportError> {
    let parsed = dsn::parse(dsn)?;
    let mut config: postgres::Config = parsed
        .config
        .parse()
        .map_err(|e: postgres::Error| ImportError::Dsn(e.to_string()))?;
    config.ssl_mode(parsed.mode);
    config.application_name("irrd-ng import");
    if parsed.mode == postgres::config::SslMode::Disable {
        config.connect(NoTls).map_err(ImportError::Connect)
    } else {
        let tls = tokio_postgres_rustls::MakeRustlsConnect::new(dsn::tls_config(&parsed)?);
        config.connect(tls).map_err(ImportError::Connect)
    }
}

/// A short, password-free description of the target for logs.
pub fn describe(dsn: &str) -> String {
    match dsn::parse(dsn)
        .ok()
        .and_then(|d| d.config.parse::<postgres::Config>().ok())
    {
        Some(c) => {
            let host = c
                .get_hosts()
                .first()
                .map(|h| match h {
                    postgres::config::Host::Tcp(h) => h.clone(),
                    postgres::config::Host::Unix(p) => p.display().to_string(),
                })
                .unwrap_or_default();
            format!("{host}/{}", c.get_dbname().unwrap_or(""))
        }
        None => "<unparseable DSN>".to_owned(),
    }
}

/// Read the whole v4 database into `sink`.
pub fn import<S: Sink>(client: &mut Client, sink: &mut S, opts: &Options) -> Result<Stats, ImportError> {
    let start = Instant::now();
    let batch_rows = opts.batch_rows.max(1);
    let (tx_msgs, rx_msgs) = mpsc::sync_channel::<Msg>(2);

    std::thread::scope(|scope| {
        let reader = scope.spawn(move || read_all(client, batch_rows, &tx_msgs));

        let mut sink_result: Result<(), ImportError> = Ok(());
        for msg in rx_msgs.iter() {
            let (table, r) = match msg {
                Msg::Begin(revision) => ("alembic_version", sink.begin(&revision)),
                Msg::Batch(batch) => (batch.table(), sink.write(batch)),
            };
            if let Err(e) = r {
                sink_result = Err(sink_error(table, e));
                break;
            }
        }
        // Hanging up makes the reader's next send fail, so it stops early.
        drop(rx_msgs);
        let stats = reader.join().unwrap_or_else(|p| std::panic::resume_unwind(p));
        sink_result?;
        let stats = stats?;
        sink.finish().map_err(|e| sink_error("database", e))?;
        info!(
            "{}",
            messages::import_done(stats.total(), start.elapsed().as_secs_f64())
        );
        Ok(stats)
    })
}

/// What the reader thread hands the sink side.
enum Msg {
    Begin(String),
    Batch(Batch),
}

fn sink_error<E: std::error::Error + Send + Sync + 'static>(table: &'static str, e: E) -> ImportError {
    ImportError::Sink {
        table,
        source: Box::new(e),
    }
}

/// Runs on the reader thread: one read-only snapshot, every table.
fn read_all(
    client: &mut Client,
    batch_rows: usize,
    out: &mpsc::SyncSender<Msg>,
) -> Result<Stats, ImportError> {
    let mut tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .map_err(ImportError::Connect)?;

    let revision = schema_revision(&mut tx)?;
    if revision != messages::V4_SCHEMA_HEAD {
        return Err(ImportError::WrongSchema(revision));
    }
    info!("{}", messages::schema_ok(&revision));
    if out.send(Msg::Begin(revision.clone())).is_err() {
        return Err(ImportError::Aborted);
    }

    let mut stats = Stats {
        schema_revision: revision,
        tables: Vec::new(),
    };
    // Referenced tables before the ones that refer to them.
    stream::<RpslObject>(&mut tx, batch_rows, out, Batch::RpslObjects, &mut stats)?;
    stream::<JournalEntry>(&mut tx, batch_rows, out, Batch::Journal, &mut stats)?;
    stream::<DatabaseStatus>(&mut tx, batch_rows, out, Batch::DatabaseStatus, &mut stats)?;
    stream::<Roa>(&mut tx, batch_rows, out, Batch::Roas, &mut stats)?;
    stream::<SuspendedObject>(&mut tx, batch_rows, out, Batch::Suspended, &mut stats)?;
    stream::<ProtectedName>(&mut tx, batch_rows, out, Batch::ProtectedNames, &mut stats)?;
    stream::<Setting>(&mut tx, batch_rows, out, Batch::Settings, &mut stats)?;
    stream::<AuthUser>(&mut tx, batch_rows, out, Batch::AuthUsers, &mut stats)?;
    stream::<AuthMntner>(&mut tx, batch_rows, out, Batch::AuthMntners, &mut stats)?;
    stream::<AuthPermission>(&mut tx, batch_rows, out, Batch::AuthPermissions, &mut stats)?;
    stream::<AuthApiToken>(&mut tx, batch_rows, out, Batch::AuthApiTokens, &mut stats)?;
    stream::<AuthWebauthn>(&mut tx, batch_rows, out, Batch::AuthWebauthn, &mut stats)?;
    stream::<ChangeLog>(&mut tx, batch_rows, out, Batch::ChangeLog, &mut stats)?;
    // Read-only: nothing to commit, and rolling back leaves no trace.
    tx.rollback().map_err(ImportError::Connect)?;
    Ok(stats)
}

fn schema_revision(tx: &mut Transaction<'_>) -> Result<String, ImportError> {
    let exists = tx
        .query_one("SELECT to_regclass('alembic_version') IS NOT NULL", &[])
        .map_err(|source| ImportError::Query {
            table: "alembic_version",
            source,
        })?;
    if !exists.get::<_, bool>(0) {
        return Err(ImportError::NoSchema);
    }
    let rows = tx
        .query("SELECT version_num FROM alembic_version", &[])
        .map_err(|source| ImportError::Query {
            table: "alembic_version",
            source,
        })?;
    match rows.as_slice() {
        [row] => Ok(row.get::<_, String>(0)),
        [] => Err(ImportError::NoSchema),
        _ => Err(ImportError::WrongSchema(
            rows.iter()
                .map(|r| r.get::<_, String>(0))
                .collect::<Vec<_>>()
                .join(","),
        )),
    }
}

fn stream<T: V4Table>(
    tx: &mut Transaction<'_>,
    batch_rows: usize,
    out: &mpsc::SyncSender<Msg>,
    wrap: fn(Vec<T>) -> Batch,
    stats: &mut Stats,
) -> Result<(), ImportError> {
    let start = Instant::now();
    let err = |source| ImportError::Query {
        table: T::TABLE,
        source,
    };
    let sql = format!("SELECT {} FROM {}", T::COLUMNS.join(", "), T::TABLE);
    let stmt = tx.prepare(&sql).map_err(err)?;
    let portal = tx.bind(&stmt, &[]).map_err(err)?;
    let max = i32::try_from(batch_rows).unwrap_or(i32::MAX);
    let mut n = 0u64;
    loop {
        let rows = tx.query_portal(&portal, max).map_err(err)?;
        let done = rows.len() < batch_rows;
        let decoded = rows
            .iter()
            .map(T::from_row)
            .collect::<Result<Vec<T>, _>>()
            .map_err(err)?;
        n += decoded.len() as u64;
        if !decoded.is_empty() && out.send(Msg::Batch(wrap(decoded))).is_err() {
            // The sink side failed and hung up; its error is reported there.
            return Err(ImportError::Aborted);
        }
        if done {
            break;
        }
    }
    info!(
        "{}",
        messages::table_done(T::TABLE, n, start.elapsed().as_secs_f64())
    );
    stats.tables.push((T::TABLE, n));
    Ok(())
}
