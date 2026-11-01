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

pub(crate) const IMPORT_USAGE: &str = "usage: irrd-ng import --from-postgres <dsn> [--store <path>] [--batch-rows <n>] \
     [--write-batch-rows <n>] [--no-load-pgp-keys]";

pub(crate) fn import_missing_value(flag: &str) -> String {
    format!("argument {flag}: expected one argument")
}

pub(crate) fn import_required(flag: &str) -> String {
    format!("the following arguments are required: {flag}")
}

pub(crate) fn import_unknown_arg(arg: &str) -> String {
    format!("unrecognized arguments: {arg}")
}

pub(crate) fn import_bad_int(flag: &str, v: &str) -> String {
    format!("argument {flag}: invalid positive int value: {v:?}")
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

pub(crate) fn import_syncing() -> String {
    "Writing the imported store to disk".to_owned()
}

pub(crate) fn import_synced(secs: f64) -> String {
    format!("Store written to disk in {secs:.1}s")
}

pub(crate) fn import_table_line(table: &str, read: u64, deleted: u64) -> String {
    format!("{table}\t{read}\tdeleted {deleted}")
}

pub(crate) fn import_store_incomplete(store: &std::path::Path) -> String {
    format!(
        "The store at {} is incomplete and will refuse to open. Run the import again into a \
         fresh store, or after removing this one.",
        store.display()
    )
}

/// `irrd` without `--foreground` and without a log file (v4's
/// `irrd/daemon/main.py`).
pub(crate) const DAEMON_NEEDS_LOGFILE: &str = "Unable to start: when not running in the foreground, you must set either log.logfile_path or log.logging_config_path in the settings";

/// `IRRd {__version__} starting, PID {pid}, PID file in {piddir}`.
pub(crate) fn irrd_starting(version: &str, pid: u32, piddir: &str) -> String {
    format!("IRRd {version} starting, PID {pid}, PID file in {piddir}")
}

/// `IRRd attempting to secure PID`.
pub(crate) const SECURING_PID: &str = "IRRd attempting to secure PID";

/// A `PidFileError`.
pub(crate) fn pid_lock_failed(piddir: &str, e: &str) -> String {
    format!("Failed to start IRRd, unable to lock PID file irrd.pid in {piddir}: {e}")
}

/// v4's generic handler in `main()`; the exception follows.
pub(crate) const MAIN_PROCESS_ERROR: &str =
    "Error occurred in main process, terminating. Error follows:";

/// What `SystemExit` prints after v4 sends itself SIGTERM.
pub(crate) const TERMINATING_ON_SIGTERM: &str = "Terminating on signal 15";

/// `main()`: started as root without `user` and `group`.
pub(crate) const ROOT_NEEDS_USER: &str =
    "Unable to start: user and group must be defined in settings when starting IRRd as root";

/// `main()`: the log file is not writable by the configured user.
pub(crate) fn logfile_not_writable(path: &str, uid: u32, gid: u32) -> String {
    format!("Unable to start: logfile {path} not writable by UID {uid} / GID {gid}")
}

/// `run_irrd()` after SIGTERM.
pub(crate) const WAITING_FOR_CHILDREN: &str =
    "Main process waiting for child processes to terminate";

/// `run_irrd()` at the end.
pub(crate) const MAIN_PROCESS_EXITING: &str = "Main process exiting";

/// `str(OSError)` for an errno: `[Errno N] text`.
pub(crate) fn errno(e: nix::errno::Errno) -> String {
    let text = std::io::Error::from_raw_os_error(e as i32).to_string();
    let text = text.split(" (os error").next().unwrap_or(&text).to_owned();
    format!("[Errno {}] {text}", e as i32)
}

/// python-daemon's `DaemonOSEnvironmentError` for the owner change.
pub(crate) fn owner_change_failed(e: nix::errno::Errno) -> String {
    format!(
        "daemon.daemon.DaemonOSEnvironmentError: Unable to change process owner ({})",
        errno(e)
    )
}

/// python-daemon's `DaemonOSEnvironmentError` for `chdir("/")`.
pub(crate) fn chdir_failed(e: &std::io::Error) -> String {
    format!("daemon.daemon.DaemonOSEnvironmentError: Unable to change working directory ({e})")
}

/// python-daemon's `DaemonProcessDetachError`.
pub(crate) fn detach_failed(e: &std::io::Error) -> String {
    format!("daemon.daemon.DaemonProcessDetachError: Failed first fork: {e}")
}

/// irrd-ng's own: where the store is (v4 has a database URL instead).
pub(crate) fn store_in(path: &std::path::Path) -> String {
    format!("Store in {}", path.display())
}

/// irrd-ng's own: replication configured without a secret.
pub(crate) const REPLICATION_NEEDS_SECRET: &str = "Unable to start: ng_replication.secret (or IRRD_NG_REPLICATION_SECRET) must be set when ng_replication.port or ng_replication.active_host is set";

/// irrd-ng's own: a replication secret too short to resist guessing. The
/// configuration check reports a short `ng_replication.secret` in the file;
/// this one also covers `IRRD_NG_REPLICATION_SECRET`.
pub(crate) const REPLICATION_SECRET_TOO_SHORT: &str = "Unable to start: ng_replication.secret (or IRRD_NG_REPLICATION_SECRET) must be at least 16 characters";

/// irrd-ng's own: a standby with nothing to follow.
/// irrd-ng's own: a whois query line over `MAX_LINE`.
pub(crate) fn whois_line_too_long(client: &str) -> String {
    format!("{client}: closed connection, query line longer than 1 MiB")
}

pub(crate) fn replication_tls(e: &str) -> String {
    format!("Unable to start: ng_replication TLS settings: {e}")
}

pub(crate) const STANDBY_WITHOUT_ACTIVE: &str = "readonly_standby is set but ng_replication.active_host is not: this standby will not receive changes";

/// irrd-ng's own: SIGHUP turned readonly_standby off.
pub(crate) const STANDBY_PROMOTED: &str = "readonly_standby is no longer set: stopped following the active, this instance now accepts writes";

/// irrd-ng's own: a `logging_config_path` file irrd-ng could not read.
pub(crate) fn logging_config_unreadable(path: &str, why: &str) -> String {
    format!(
        "{path} could not be read as a logging configuration ({why} is not supported); using the default logging to stderr"
    )
}

/// irrd-ng's own: part of a `logging_config_path` file left out.
pub(crate) fn logging_config_notice(notice: &str) -> String {
    format!("log.logging_config_path: {notice}")
}

/// irrd-ng's own: a listening socket could not be opened.
pub(crate) fn bind_failed(what: &str, interface: &str, port: u16, e: &std::io::Error) -> String {
    format!("Unable to start the {what} server on ('{interface}', {port}): {e}")
}

/// `Whois server shutting down` (v4's `irrd/server/whois/server.py`).
pub(crate) const WHOIS_SHUTTING_DOWN: &str = "Whois server shutting down";

/// irrd-ng's own: a thread panicked (the query, if any, is logged by the
/// engine).
pub(crate) fn panicked(thread: &str, info: &str, backtrace: &str) -> String {
    format!("Thread {thread} panicked: {info}\n{backtrace}")
}

/// irrd-ng's own: the store writer died, so the daemon stops.
pub(crate) const WRITER_PANICKED: &str =
    "The store writer thread panicked; irrd-ng cannot write to the store and is shutting down";

// irrd/scripts/mirror_force_reload.py

/// `set_force_reload()`: not a mirror.
pub(crate) fn force_reload_not_mirror(source: &str) -> String {
    format!(
        "You can only set the force reload flag for sources that are a mirror. Source {source} has \
         neither nrtm4_client_notification_file_url, nrtm_host, or import_source set."
    )
}

/// `set_force_reload()`: an NRTMv4 client keeps its keys.
pub(crate) fn force_reload_nrtm4_note(source: &str) -> String {
    format!(
        "Note: the reload flag will be set on the source, but existing NRTMv4 client key information \
         is kept. To revert to the key currently set in the \
         sources.{source}.nrtm4_client_initial_public_key setting, use 'irrdctl nrtm4 \
         client-clear-known-keys'"
    )
}

// irrd/scripts/irrd_control.py

/// `check_readonly_standby`.
pub(crate) const CTL_READONLY_STANDBY: &str =
    "Unable to run this command, because readonly_standby is set.";

/// `client_clear_known_keys`: not an NRTMv4 client.
pub(crate) fn ctl_not_nrtm4_client(source: &str) -> String {
    format!("Source {source} is not configured as an NRTMv4 client")
}

/// `client_clear_known_keys`: no status row.
pub(crate) fn ctl_no_known_keys(source: &str) -> String {
    format!("No current known keys for source {source}")
}

/// `client_clear_known_keys`: done.
pub(crate) fn ctl_known_keys_removed(source: &str) -> String {
    format!(
        "Known keys removed, expected key is now taken from the \
         sources.{source}.nrtm4_client_initial_public_key setting.\nNote that other data for this \
         source is not reloaded - for that use irrd_mirror_force_reload."
    )
}

/// `client_clear_known_keys`: the log line.
pub(crate) fn ctl_known_keys_removed_log(source: &str) -> String {
    format!("{source}: known NRTMv4 client keys removed")
}

/// `generate_private_key`
pub(crate) fn ctl_generated_key(private_pem: &str, public_pem: &str) -> String {
    format!(
        "Private key:\n\n{private_pem}\nCorresponding public key:\n\n{public_pem}\nNote: this key has not been configured in IRRD, that is a manual step. This is only a convenience command."
    )
}

/// `server_show_public_key`: not an NRTMv4 server.
pub(crate) fn ctl_not_nrtm4_server(source: &str) -> String {
    format!("Source {source} is not configured as an NRTMv4 server")
}

/// `server_show_public_key`: the current key.
pub(crate) fn ctl_current_public_key(source: &str, public_pem: &str) -> String {
    format!(
        "Current public key for {source} NRTMv4 server (from nrtm4_server_private_key):\n\n{public_pem}"
    )
}

/// `server_show_public_key`: the next key.
pub(crate) fn ctl_next_public_key(public_pem: &str) -> String {
    format!("Next key (from nrtm4_server_private_key_next):\n{public_pem}")
}

// irrd/scripts/expire_journal.py

/// Unparseable `--expire-before`.
pub(crate) const EXPIRE_INVALID_DATE: &str = "Invalid date or date format";

/// `--expire-before` too recent.
pub(crate) fn expire_minimum(date: &str) -> String {
    format!("Minimum expiry is {date}")
}

/// Nothing matched.
pub(crate) const EXPIRE_NOTHING: &str = "No journal entries found to expire.";

/// The confirmation prompt (`textwrap.dedent(...).strip()`).
pub(crate) fn expire_confirm(count: usize, source: &str) -> String {
    format!(
        "Found {count} journal entries to delete from the journal for {source}.\nThis is the only record of history kept by IRRd itself.\nAfter deletion, this can not be recovered.\n\nTo confirm deleting these entries for {source}, type 'yes':"
    )
}

/// Not confirmed.
pub(crate) const EXPIRE_CANCELLED: &str = "Deletion cancelled.";

/// Done.
pub(crate) const EXPIRE_COMPLETE: &str = "Expiry complete.";

/// `input()` at end of file: Python's `EOFError`.
pub(crate) const EOF_ERROR: &str = "EOFError: EOF when reading a line";

/// irrd-ng: `run-job` with an unknown job name.
pub(crate) fn unknown_job(job: &str) -> String {
    format!("irrd-ng run-job: unknown job {job:?} (roa-import, scopefilter, route-preference)")
}

/// `irrd-ng import`: the keyring filled from the imported key-certs.
pub(crate) fn import_keyring(keys: usize) -> String {
    format!("pgp_keyring: {keys} keys loaded from key-cert objects")
}
