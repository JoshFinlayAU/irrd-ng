//! User-facing strings of the v4 import.
//!
//! v4 has no import tool, so these are irrd-ng's own. They follow v4's
//! loader in tone and shape ("File import for SOURCE: N objects read, ...").

/// The only alembic revision accepted: the head of IRRd 4.5.0 to 4.5.4.
pub const V4_SCHEMA_HEAD: &str = "e1e649b5f8bb";

pub fn dsn_scheme(scheme: &str) -> String {
    format!("Unsupported database URL scheme {scheme:?}, expected postgresql://")
}

pub fn dsn_sslmode(mode: &str) -> String {
    format!("Invalid sslmode {mode:?} in database URL")
}

pub fn root_cert(path: &str, err: &str) -> String {
    format!("Unable to load sslrootcert {path}: {err}")
}

pub fn no_schema() -> String {
    "The source database has no alembic_version table; it is not an IRRd v4 database".to_owned()
}

pub fn wrong_schema(found: &str) -> String {
    format!(
        "The source database is at schema revision {found}, but only IRRd 4.5.x \
         (revision {V4_SCHEMA_HEAD}) can be imported. Upgrade it with v4's \
         irrd_database_upgrade first."
    )
}

pub fn connecting(target: &str) -> String {
    format!("Importing from IRRd v4 database at {target}, read-only")
}

pub fn schema_ok(revision: &str) -> String {
    format!("Source database schema revision {revision} (IRRd 4.5.x)")
}

pub fn table_done(table: &str, rows: u64, secs: f64) -> String {
    format!("Import of {table}: {rows} rows read in {secs:.1}s")
}

pub fn import_done(rows: u64, secs: f64) -> String {
    format!("Import from IRRd v4 complete: {rows} rows in {secs:.1}s")
}

pub fn query_failed(table: &str) -> String {
    format!("Reading {table} from the source database failed")
}

pub fn sink_failed(table: &str) -> String {
    format!("Writing {table} rows to the store failed")
}

pub fn aborted() -> String {
    "Import aborted".to_owned()
}

pub fn bad_value(what: &str, value: &str) -> String {
    format!("Unexpected value in {what}: {value}")
}

pub fn ip_size_mismatch(what: &str, v4: &str, derived: &str) -> String {
    format!("{what} is {v4} in the source, but {derived} from ip_first and ip_last")
}
