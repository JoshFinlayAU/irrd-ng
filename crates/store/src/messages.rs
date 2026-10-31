//! User-facing strings, copied verbatim from IRRd v4 at the pinned baseline.
//!
//! Every message a client, operator or mail recipient can see lives here, so a
//! parity fix to wording touches exactly one place. Strings marked irrd-ng
//! have no v4 counterpart (v4 has no embedded store).

use std::path::Path;

/// `DatabaseHandler._check_write_permitted` (`irrd/storage/database_handler.py`).
pub const READONLY_WRITE: &str =
    "Attempted to write to SQL database from readonly database handler";

/// `DatabaseHandler._check_single_row_match`.
pub fn no_row_matched(user_identifier: &str) -> String {
    format!("Attempted to remove/suspend object {user_identifier}, but no database row matched")
}

/// `DatabaseHandler.suspend_rpsl_object` (v4's typo "obect" included).
pub fn suspend_missing(pk: &str) -> String {
    format!("Attempt to suspend obect with PK {pk} which does not exist")
}

/// `DatabaseHandler.set_force_reload` (v4's typo "wll" included).
pub fn force_reload_set(source: &str, synchronised_serials: bool) -> String {
    let s = if synchronised_serials {
        "True"
    } else {
        "False"
    };
    format!(
        "force_reload flag set for {source}, serial synchronisation will be {s} for \
         current settings, actual reload process wll take place in next scheduled importer run"
    )
}

/// PostgreSQL's unique violation for `rpsl_objects_history_serial_nrtm_source_unique`,
/// as v4 would surface it from psycopg (first line).
pub fn journal_serial_conflict(source: &str, serial: i64) -> String {
    format!(
        "duplicate key value violates unique constraint \"rpsl_objects_history_serial_nrtm_source_unique\"\n\
         DETAIL:  Key (serial_nrtm, source)=({serial}, {source}) already exists."
    )
}

/// PostgreSQL's NOT NULL violation for `serial_nrtm` (a synchronised source
/// with no source serial), first line as psycopg reports it.
pub const JOURNAL_SERIAL_NULL: &str = "null value in column \"serial_nrtm\" of relation \"rpsl_database_journal\" violates not-null constraint";

/// PostgreSQL's unique violation for `roa_object_prefix_asn_maxlength_unique`.
pub fn roa_conflict(prefix: &str, asn: i64, max_length: i64, trust_anchor: &str) -> String {
    format!(
        "duplicate key value violates unique constraint \"roa_object_prefix_asn_maxlength_unique\"\n\
         DETAIL:  Key (prefix, asn, max_length, trust_anchor)=({prefix}, {asn}, {max_length}, {trust_anchor}) already exists."
    )
}

/// irrd-ng: the store could not be opened.
pub fn open_failed(path: &Path, e: &heed::Error) -> String {
    format!(
        "unable to open the irrd-ng store at {}: {e}",
        path.display()
    )
}

/// irrd-ng: a read-only open of a store that was never created.
pub fn not_initialised(path: &Path) -> String {
    format!(
        "the irrd-ng store at {} has not been initialised",
        path.display()
    )
}

/// irrd-ng: the store is newer than this build.
pub fn schema_too_new(found: u32, supported: u32) -> String {
    format!(
        "the irrd-ng store has schema version {found}, but this irrd-ng supports up to version {supported}"
    )
}

/// irrd-ng: the store needs a migration.
pub fn schema_too_old(found: u32, supported: u32) -> String {
    format!(
        "the irrd-ng store has schema version {found} and needs to be upgraded to version {supported}"
    )
}

/// irrd-ng: no migration path.
pub fn no_migration(from: u32, to: u32) -> String {
    format!("no migration from store schema version {from} to {to}")
}

/// irrd-ng: a migration step is running.
pub fn migrating(from: u32, to: u32) -> String {
    format!("Migrating the irrd-ng store from schema version {from} to {to}")
}

/// irrd-ng: the map was grown.
pub fn map_resized(size: usize) -> String {
    format!("Growing the irrd-ng store map size to {size} bytes")
}

/// irrd-ng: an interrupted whole-store bulk load (the v4 import).
pub fn load_incomplete(path: &Path, label: &str) -> String {
    format!(
        "the irrd-ng store at {} holds an incomplete bulk load ({label}): \
         the load was interrupted and the store may be partial or damaged. \
         Remove the store and load or import again",
        path.display()
    )
}

/// irrd-ng: an interrupted bulk load of one source, found at open.
pub fn source_load_interrupted(source: &str) -> String {
    format!(
        "A bulk load of source {source} was interrupted by a crash; the data of {source} may \
         be missing its last changes. force_reload is set for {source}: reload it (mirrored \
         sources reload on their next import run, others need irrd_load_database)"
    )
}
