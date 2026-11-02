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

/// irrd-ng: `irrd-ng migrate-check`, the pre-flight for moving from IRRd v4.
/// Plain operator English; the package's maintainer scripts print it as is.
pub(crate) mod migrate {
    use std::fmt::Write as _;

    pub(crate) const USAGE: &str = "usage: irrd-ng migrate-check [--config CONFIG_FILE_PATH] [--quiet | --json]\n\n\
Checks whether irrd-ng can take over from IRRd v4 on this host: whether v4 is\n\
still running, whether the irrd-ng store holds an imported database, how large\n\
the v4 database is and whether there is enough free disk space for the import.\n\
Prints the steps to finish the migration.\n\n\
options:\n  \
--config PATH  the irrd.yaml to read (default: /etc/irrd.yaml)\n  \
--quiet        print nothing, only set the exit code\n  \
--json         print the findings as one JSON object\n\n\
exit codes: 0 ready to start, 10 IRRd v4 (or another program on its ports) is\n\
running, 11 the store is not imported, 12 not enough disk space for the import,\n\
13 configuration problem, 2 usage error.";

    pub(crate) fn bad_arg(arg: &str) -> String {
        format!("irrd-ng migrate-check: error: unrecognized arguments: {arg}")
    }

    pub(crate) fn missing_value(flag: &str) -> String {
        format!("irrd-ng migrate-check: error: argument {flag}: expected one argument")
    }

    pub(crate) const QUIET_AND_JSON: &str =
        "irrd-ng migrate-check: error: --quiet and --json cannot be combined";

    pub(crate) const TITLE: &str = "irrd-ng migration check";

    /// `1370000` as `1,370,000`.
    pub(crate) fn grouped(n: u64) -> String {
        let digits = n.to_string();
        let mut out = String::with_capacity(digits.len() + digits.len() / 3);
        for (i, c) in digits.chars().enumerate() {
            if i > 0 && (digits.len() - i).is_multiple_of(3) {
                out.push(',');
            }
            out.push(c);
        }
        out
    }

    /// A labelled line of the report, continuation lines indented under
    /// the value.
    pub(crate) fn field(out: &mut String, label: &str, lines: &[String]) {
        for (i, line) in lines.iter().enumerate() {
            let label = if i == 0 { label } else { "" };
            let _ = writeln!(out, "{label:<14}{line}");
        }
    }

    pub(crate) const L_CONFIG: &str = "Config:";
    pub(crate) const L_V4: &str = "IRRd v4:";
    pub(crate) const L_NG: &str = "irrd-ng:";
    pub(crate) const L_STORE: &str = "Store:";
    pub(crate) const L_DB: &str = "v4 database:";
    pub(crate) const L_SPACE: &str = "Disk space:";
    pub(crate) const L_NOTES: &str = "Notes:";

    pub(crate) fn config_valid(path: &str) -> String {
        format!("{path} is valid")
    }

    pub(crate) fn config_missing(path: &str) -> String {
        format!("{path} does not exist")
    }

    pub(crate) fn config_invalid(path: &str) -> String {
        format!("{path} is not valid:")
    }

    pub(crate) const V4_NOT_RUNNING: &str = "not running";
    pub(crate) const V4_RUNNING: &str = "RUNNING";

    pub(crate) const V4_SYSTEMD: &str = "- systemd reports irrd.service as active";

    pub(crate) fn v4_pidfile(path: &str, pid: u32, command: &str) -> String {
        format!("- PID {pid} from {path} is IRRd v4: {command}")
    }

    pub(crate) fn port_held_by_v4(port: u16, what: &str, pid: u32, command: &str) -> String {
        format!("- port {port} ({what}) is held by IRRd v4, PID {pid}: {command}")
    }

    pub(crate) fn port_held_by_other(port: u16, what: &str, pid: u32, command: &str) -> String {
        format!("- port {port} ({what}) is held by another program, PID {pid}: {command}")
    }

    pub(crate) fn port_held_unknown(port: u16, what: &str) -> String {
        format!(
            "- port {port} ({what}) is in use by a program this check cannot see; run it as root to find out which"
        )
    }

    pub(crate) const NG_RUNNING: &str = "running";
    pub(crate) const NG_NOT_RUNNING: &str = "not running";

    pub(crate) fn store_imported(path: &str, sources: usize, objects: u64, size: &str) -> String {
        format!(
            "{path} holds imported data: {sources} sources, {} objects, {size} on disk",
            grouped(objects)
        )
    }

    pub(crate) fn store_needs_upgrade(path: &str, size: &str) -> String {
        format!(
            "{path} holds data from an older irrd-ng ({size} on disk); irrd-ng upgrades it when it starts"
        )
    }

    pub(crate) fn store_absent(path: &str) -> String {
        format!("{path} holds no store yet: nothing has been imported")
    }

    pub(crate) fn store_empty(path: &str) -> String {
        format!("{path} holds an empty store: nothing has been imported")
    }

    pub(crate) fn store_incomplete(path: &str) -> String {
        format!(
            "{path} holds an import or load that did not finish (or is running right now); irrd-ng will not open it until an import completes"
        )
    }

    pub(crate) fn store_unusable(path: &str, why: &str) -> String {
        format!("{path} cannot be used: {why}")
    }

    pub(crate) const DB_SKIPPED_IMPORTED: &str =
        "not checked, because the store is already imported";
    pub(crate) const DB_SKIPPED_NO_CONFIG: &str =
        "not checked, because there is no valid irrd.yaml";
    pub(crate) const DB_NO_URL: &str = "irrd.yaml sets no database_url";

    pub(crate) fn db_size(
        target: &str,
        db_bytes: Option<&str>,
        objects: u64,
        journal: u64,
        roas: u64,
        approximate: bool,
    ) -> Vec<String> {
        let size = db_bytes.map_or_else(String::new, |s| format!(", {s} in PostgreSQL"));
        let about = if approximate { "about " } else { "" };
        vec![
            format!("{target}{size}"),
            format!(
                "{about}{} RPSL objects, {about}{} journal entries, {about}{} ROAs",
                grouped(objects),
                grouped(journal),
                grouped(roas)
            ),
        ]
    }

    pub(crate) fn db_unreachable(target: &str, error: &str, masked_url: &str) -> Vec<String> {
        vec![
            format!("could not read {target}: {error}"),
            "The import needs this database. Check that PostgreSQL is running and that this works:"
                .to_owned(),
            format!("  psql '{masked_url}' -c 'select count(*) from rpsl_objects'"),
            "If database_url uses a local socket with peer authentication, run this check as the irrd user: sudo -u irrd irrd-ng migrate-check".to_owned(),
        ]
    }

    pub(crate) fn space_known(
        estimate: &str,
        needed: &str,
        fs_path: &str,
        free: &str,
        enough: bool,
    ) -> Vec<String> {
        let verdict = if enough { "ENOUGH" } else { "NOT ENOUGH" };
        vec![
            format!("the store will be about {estimate}; the import needs {needed} free"),
            format!("on the filesystem holding {fs_path}, which has {free} free: {verdict}"),
            "(estimate: 1.45 KB per RPSL object, journal entry and ROA, from measured imports; needed: twice the estimate, because LMDB writes copies of pages and a full import can briefly need double, plus 1 GiB for the next step of map growth, less what the store already uses)".to_owned(),
        ]
    }

    pub(crate) fn space_unknown(fs_path: &str, free: &str) -> Vec<String> {
        vec![
            format!("{free} free on the filesystem holding {fs_path}; UNKNOWN whether that is enough"),
            "Without the v4 database's size there is no estimate. As a guide, allow 3 KB of free space per RPSL object and journal entry (a full RADB mirror of 1.4 million objects builds a 1.8 GB store).".to_owned(),
        ]
    }

    pub(crate) fn space_imported(store: &str, fs_path: &str, free: &str) -> String {
        format!(
            "the store uses {store}; {free} free on the filesystem holding {fs_path} (keep at least the store's size free, so it can grow)"
        )
    }

    pub(crate) fn space_unreadable(fs_path: &str, error: &str) -> String {
        format!("could not read the free space of {fs_path}: {error}")
    }

    pub(crate) fn note_piddir(piddir: &str) -> String {
        format!(
            "piddir in irrd.yaml is {piddir}, but the irrd-ng service expects /run/irrd. Either set piddir: /run/irrd, or run systemctl edit irrd-ng and set PIDFile={piddir}/irrd.pid in the [Service] section."
        )
    }

    pub(crate) fn note_config_path(path: &str) -> String {
        format!(
            "the irrd-ng service reads /etc/irrd.yaml, not {path}. Link or copy the file there, or change ExecStart with systemctl edit irrd-ng."
        )
    }

    pub(crate) fn note_no_user(user: &str) -> String {
        format!(
            "irrd.yaml sets user {user}, which does not exist on this host; irrd-ng will refuse to start until it does."
        )
    }

    pub(crate) fn note_store_owner(path: &str, owner: &str, user: &str) -> String {
        format!(
            "{path} belongs to {owner}, but irrd-ng runs as {user}. Fix it with: sudo chown -R {user}: {path}"
        )
    }

    pub(crate) const NOTE_NO_USER_SETTING: &str = "irrd.yaml sets no user. irrd-ng, like v4, refuses to keep running as root; set user and group (usually irrd).";

    pub(crate) const RESULT_READY: &str = "Result: READY. irrd-ng can be started.";
    pub(crate) const RESULT_RUNNING: &str = "Result: READY. irrd-ng is running.";
    pub(crate) const RESULT_CONFIG: &str =
        "Result: NOT READY, because irrd.yaml is missing or not valid.";
    pub(crate) const RESULT_V4: &str =
        "Result: NOT READY, because IRRd v4 (or another program on its ports) is still running.";
    pub(crate) const RESULT_SPACE: &str =
        "Result: NOT READY, because there is not enough free disk space for the import.";
    pub(crate) const RESULT_NOT_IMPORTED: &str =
        "Result: NOT READY, because the v4 database has not been imported yet.";

    pub(crate) const NEXT: &str = "Next steps:";

    pub(crate) fn step_config_missing(path: &str) -> String {
        format!(
            "Put the irrd.yaml of your IRRd v4 installation at {path}. irrd-ng reads the same file, unchanged. If v4 keeps it elsewhere, link it: sudo ln -s /path/to/irrd.yaml {path}. For a new installation with no v4, write one as for IRRd 4.5 (database_url and redis_url are required but not used). Then run: {}",
            recheck(path)
        )
    }

    pub(crate) fn step_config_invalid(path: &str) -> String {
        format!(
            "Fix the errors in {path} listed above (irrd-ng accepts exactly what IRRd 4.5.4 accepts), then run: {}",
            recheck(path)
        )
    }

    pub(crate) const STEP_STOP_V4: &str = "Stop IRRd v4 and keep it from starting again:";
    pub(crate) const STOP_V4_SYSTEMD: [&str; 2] =
        ["sudo systemctl stop irrd", "sudo systemctl disable irrd"];

    pub(crate) fn stop_v4_pidfile(pidfile: &str) -> String {
        format!("sudo kill $(cat {pidfile})")
    }

    pub(crate) fn stop_v4_no_systemd(pidfile: &str) -> String {
        format!(
            "If v4 is not run by systemd, stop it with its PID file (v4 shuts down cleanly on SIGTERM) and remove whatever starts it at boot. Check it is gone before going on: no process listening on its ports, and no {pidfile}."
        )
    }

    pub(crate) fn stop_other(port: u16) -> String {
        format!(
            "Stop the program holding port {port}, or move irrd-ng to another port in irrd.yaml."
        )
    }

    pub(crate) const KEEP_PG: &str =
        "Keep PostgreSQL running: the import reads from it. Redis can be stopped.";

    pub(crate) const STEP_IMPORT: &str =
        "Import the v4 database into the irrd-ng store, as the user irrd-ng runs as:";

    pub(crate) fn import_command(user: &str, store: &str, masked_url: &str) -> String {
        format!(
            "sudo -u {user} env IRRD_NG_STORE_PATH={store} irrd-ng import --from-postgres '{masked_url}'"
        )
    }

    pub(crate) fn import_note(mask: &str, has_password: bool) -> String {
        let safe = "The import only reads from PostgreSQL, keeps every NRTM serial, and is safe to run again.";
        if has_password {
            format!("Replace {mask} with the password from database_url in irrd.yaml. {safe}")
        } else {
            safe.to_owned()
        }
    }

    pub(crate) fn import_command_no_url(user: &str, store: &str) -> String {
        format!(
            "sudo -u {user} env IRRD_NG_STORE_PATH={store} irrd-ng import --from-postgres 'postgresql://USER:PASSWORD@HOST/DATABASE'"
        )
    }

    pub(crate) const IMPORT_URL_NOTE: &str = "Use the database_url from the irrd.yaml of your IRRd v4 installation. The import only reads from PostgreSQL, keeps every NRTM serial, and is safe to run again.";

    pub(crate) fn recheck(config_path: &str) -> String {
        if config_path == config::CONFIG_PATH_DEFAULT {
            "sudo irrd-ng migrate-check".to_owned()
        } else {
            format!("sudo irrd-ng migrate-check --config {config_path}")
        }
    }

    pub(crate) fn import_space(needed: &str, free: &str, enough: bool) -> String {
        if enough {
            format!("It needs about {needed} free disk space; {free} is free, which is enough.")
        } else {
            format!(
                "It needs about {needed} free disk space, but only {free} is free. Free up space first, or set IRRD_NG_STORE_PATH (here and in the service, with systemctl edit irrd-ng) to a larger filesystem."
            )
        }
    }

    pub(crate) const NEW_INSTALL: &str = "If this is a new installation with no IRRd v4 data to bring over, skip the import: irrd-ng creates the store when it starts and fills it by mirroring or with irrd_load_database.";

    pub(crate) const STEP_START: &str = "Start irrd-ng, now and at boot:";
    pub(crate) const START_COMMAND: &str = "sudo systemctl enable --now irrd-ng";

    pub(crate) const STEP_CHECK: &str = "Check that it answers:";

    pub(crate) fn check_commands(whois_port: u16) -> [String; 3] {
        let port = if whois_port == 43 {
            String::new()
        } else {
            format!(" -p {whois_port}")
        };
        [
            format!("whois -h localhost{port} '!v'      (answers with version 4.5.4, as v4 did)"),
            "systemctl status irrd-ng".to_owned(),
            "journalctl -u irrd-ng".to_owned(),
        ]
    }

    pub(crate) const STEP_ROLLBACK: &str = "To go back to IRRd v4 (its database is untouched):";
    pub(crate) const ROLLBACK_COMMANDS: [&str; 2] = [
        "sudo systemctl disable --now irrd-ng",
        "sudo systemctl enable --now irrd",
    ];

    pub(crate) const PG_REDIS: &str = "irrd-ng does not use PostgreSQL or Redis. Keep v4's PostgreSQL, Redis and a pg_dump of its database until you are satisfied with irrd-ng, so rolling back stays possible.";

    pub(crate) const RUNBOOK: &str =
        "The full runbook is /usr/share/doc/irrd-ng/docs/migration.md.";
}
