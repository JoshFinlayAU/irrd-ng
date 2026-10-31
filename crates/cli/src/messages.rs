//! User-facing strings for the multicall dispatcher.
//!
//! Strings that v4 itself prints belong to each tool and are copied verbatim
//! from the pinned v4 source. These ones exist only in irrd-ng, because v4
//! installs separate scripts and has no dispatcher.

pub(crate) fn usage(tools: &[&str]) -> String {
    format!(
        "usage: irrd-ng <tool> [args...]\n\ntools: {}",
        tools.join(", ")
    )
}

pub(crate) fn unknown_tool(name: &str) -> String {
    format!("irrd-ng: unknown tool name {name:?}")
}

pub(crate) fn not_implemented(name: &str) -> String {
    format!("{name}: not implemented yet")
}

pub(crate) const IMPORT_USAGE: &str =
    "usage: irrd-ng import --from-postgres <dsn> [--store <path>] [--batch-rows <n>]";

pub(crate) fn import_missing_value(flag: &str) -> String {
    format!("argument {flag}: expected one argument")
}

pub(crate) fn import_required(flag: &str) -> String {
    format!("the following arguments are required: {flag}")
}

pub(crate) fn import_unknown_arg(arg: &str) -> String {
    format!("unrecognized arguments: {arg}")
}

pub(crate) fn import_bad_batch(v: &str) -> String {
    format!("argument --batch-rows: invalid positive int value: {v:?}")
}

pub(crate) fn import_failed(err: &str) -> String {
    format!("Import from IRRd v4 failed: {err}")
}

pub(crate) fn import_summary(read: u64, written: u64, serial_global: i64, secs: f64) -> String {
    format!(
        "Imported {read} rows ({written} written), serial_global continues after \
         {serial_global}, in {secs:.1}s"
    )
}
// Strings v4's database scripts print (irrd/scripts/load_database.py,
// update_database.py, database_upgrade.py, database_downgrade.py).

/// `main()`: refuse to run on a standby.
pub(crate) const READONLY_STANDBY: &str = "Unable to run, because readonly_standby is set";

/// `load()` / `update()`: the source is mirrored from elsewhere.
pub(crate) fn import_source_set(source: &str) -> String {
    format!(
        "Error: to use this command, import_source and import_serial_source for source {source} must not be set."
    )
}

/// `load()` / `update()`: the import returned an error.
pub(crate) fn error_processing_object(error: &str) -> String {
    format!("Error occurred while processing object:\n{error}")
}

/// `database_upgrade.run()`.
pub(crate) const UPGRADE_SUCCESSFUL: &str = "Upgrade successful, or already on latest version.";

/// `database_downgrade.run()`.
pub(crate) const DOWNGRADE_SUCCESSFUL: &str = "Downgrade successful, or already on this version.";

/// The last line of the traceback v4 prints when `config_init` fails.
pub(crate) fn configuration_error(e: &str) -> String {
    format!("irrd.conf.ConfigurationError: {e}")
}

/// The last line of the traceback for an unreadable input file.
pub(crate) fn os_error(e: &std::io::Error, path: &str) -> String {
    let class = match e.kind() {
        std::io::ErrorKind::NotFound => "FileNotFoundError",
        std::io::ErrorKind::PermissionDenied => "PermissionError",
        std::io::ErrorKind::IsADirectory => "IsADirectoryError",
        _ => "OSError",
    };
    let text = e.to_string();
    let text = text.split(" (os error").next().unwrap_or(&text).to_owned();
    match e.raw_os_error() {
        Some(errno) => format!(
            "{class}: [Errno {errno}] {text}: {}",
            config::str_repr(path)
        ),
        None => format!("{class}: {text}: {}", config::str_repr(path)),
    }
}

/// alembic's `CommandError` for an unknown revision.
pub(crate) fn cant_locate_revision(version: &str) -> String {
    format!(
        "alembic.util.exc.CommandError: Can't locate revision identified by {}",
        config::str_repr(version)
    )
}

/// alembic's `CommandError` for a relative revision out of range.
pub(crate) fn relative_revision(version: &str, n: i64) -> String {
    format!(
        "alembic.util.exc.CommandError: Relative revision {version} didn't produce {n} migrations"
    )
}

/// irrd-ng: `export-jsonl` with an unknown table.
pub(crate) fn unknown_export_table(table: &str) -> String {
    format!("irrd-ng export-jsonl: unknown table {table:?}")
}

/// irrd-ng: `export-jsonl --table all` needs a directory.
pub(crate) const EXPORT_ALL_NEEDS_DIR: &str =
    "irrd-ng export-jsonl: --table all needs --output-dir";
