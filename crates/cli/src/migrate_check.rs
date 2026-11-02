//! `irrd-ng migrate-check`: the pre-flight for replacing IRRd v4.
//!
//!   irrd-ng migrate-check [--config PATH] [--quiet | --json]
//!
//! Reads `irrd.yaml` and reports whether IRRd v4 is still running on this
//! host (its systemd unit, its PID file, or anything other than irrd-ng on
//! the configured whois and HTTP ports), whether the irrd-ng store holds an
//! imported database, how large the v4 database is (read-only, short
//! timeouts) and whether the filesystem holding the store has room for the
//! import. It then prints the steps that remain. The exit code says whether
//! irrd-ng is ready to start; the Debian package's maintainer scripts use it
//! to decide whether to start the service.
//!
//! Nothing here writes anywhere, with one exception: opening an existing
//! store read-only may create LMDB's `lock.mdb` beside `data.mdb`, which is
//! then given to the owner of `data.mdb` so the daemon can still open it.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use config::Configuration;
use serde_json::json;
use store::{Store, StoreError, StoreOptions};

use crate::messages::migrate as m;
use crate::settings;

/// Exit codes, also documented in the usage text and the package scripts.
pub(crate) const EXIT_READY: u8 = 0;
pub(crate) const EXIT_USAGE: u8 = 2;
pub(crate) const EXIT_V4_RUNNING: u8 = 10;
pub(crate) const EXIT_NOT_IMPORTED: u8 = 11;
pub(crate) const EXIT_NO_SPACE: u8 = 12;
pub(crate) const EXIT_CONFIG: u8 = 13;

/// Store bytes per RPSL object, journal entry and ROA. Measured: a full
/// RADB import (1.37 million objects) built a 1,839 MB store, about 1,340
/// bytes per object, and a 6,444,813-row production database a 7.7 GB
/// store, about 1,200 bytes per row. Rounded up from the larger of the two.
pub(crate) const BYTES_PER_ROW: u64 = 1450;
/// The least the LMDB map grows by (`StoreOptions::growth_step`).
pub(crate) const GROWTH_STEP: u64 = 1 << 30;
/// A full import is one long series of large write transactions; LMDB
/// keeps the old copy of every page it rewrites until the transaction
/// commits, so the data file can briefly need about double.
pub(crate) const REWRITE_FACTOR: u64 = 2;

/// The unit's piddir (`RuntimeDirectory=irrd`).
const UNIT_PIDDIR: &str = "/run/irrd";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const STATEMENT_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Output {
    Text,
    Quiet,
    Json,
}

#[derive(Debug)]
struct Args {
    config: Option<String>,
    output: Output,
}

fn parse(args: &[OsString]) -> Result<Option<Args>, String> {
    let mut config = None;
    let mut quiet = false;
    let mut json = false;
    let mut it = args
        .iter()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned());
    while let Some(arg) = it.next() {
        match arg.split_once('=') {
            Some(("--config", v)) => config = Some(v.to_owned()),
            _ => match arg.as_str() {
                "--config" => {
                    config = Some(it.next().ok_or_else(|| m::missing_value("--config"))?);
                }
                "--quiet" | "-q" => quiet = true,
                "--json" => json = true,
                "-h" | "--help" => return Ok(None),
                other => return Err(m::bad_arg(other)),
            },
        }
    }
    let output = match (quiet, json) {
        (true, true) => return Err(m::QUIET_AND_JSON.to_owned()),
        (true, false) => Output::Quiet,
        (false, true) => Output::Json,
        (false, false) => Output::Text,
    };
    Ok(Some(Args { config, output }))
}

// ---- pure logic ----------------------------------------------------------

/// What a process is, for deciding whether v4 is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcKind {
    IrrdNg,
    V4,
    Other,
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Classify a process from its `/proc/<pid>/exe` target (if readable),
/// what its `argv[0]` resolves to (if it is a path), and its command line.
/// irrd-ng is any binary named `irrd-ng*`, also when it was started under
/// a tool name (`irrd` is a symlink to it). IRRd v4 is a Python process
/// with `irrd` in its command line, or one of the process titles v4 sets
/// (`irrd-whois-worker`, `irrd-http-server-listener` and the like).
pub(crate) fn classify(exe: Option<&str>, argv0_target: Option<&str>, argv: &[String]) -> ProcKind {
    let exe = exe.map(|e| e.trim_end_matches(" (deleted)"));
    let is_ng = |p: &str| basename(p).starts_with("irrd-ng");
    if exe.is_some_and(is_ng) || argv0_target.is_some_and(is_ng) {
        return ProcKind::IrrdNg;
    }
    // Under qemu-user the exe is the emulator; the binary follows it.
    if argv.iter().take(2).any(|a| is_ng(a)) {
        return ProcKind::IrrdNg;
    }
    let argv0 = argv.first().map(String::as_str).unwrap_or_default();
    let title = basename(argv0.split_whitespace().next().unwrap_or_default());
    if title.starts_with("irrd-") || title == "irrd" {
        return ProcKind::V4;
    }
    let python =
        exe.is_some_and(|e| basename(e).starts_with("python")) || title.starts_with("python");
    if python && argv.iter().any(|a| basename(a).starts_with("irrd")) {
        return ProcKind::V4;
    }
    ProcKind::Other
}

/// Listening TCP sockets in a `/proc/net/tcp` or `/proc/net/tcp6` table:
/// (local port, socket inode).
pub(crate) fn parse_listening(table: &str) -> Vec<(u16, u64)> {
    const LISTEN: &str = "0A";
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 || f[3] != LISTEN {
                return None;
            }
            let port = u16::from_str_radix(f[1].rsplit(':').next()?, 16).ok()?;
            let inode = f[9].parse().ok()?;
            Some((port, inode))
        })
        .collect()
}

/// The inode of a `/proc/<pid>/fd/<n>` link target `socket:[12345]`.
pub(crate) fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// The PID in a PID file: the first line, as v4 and irrd-ng write it.
pub(crate) fn parse_pidfile(text: &str) -> Option<u32> {
    text.lines().next()?.trim().parse().ok().filter(|p| *p > 0)
}

/// How much store an import builds and how much free space it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Estimate {
    pub(crate) store_bytes: u64,
    pub(crate) required_free: u64,
}

/// The estimate for `rows` RPSL objects, journal entries and ROAs, into a
/// store that already takes `existing` bytes on disk: twice the store, for
/// copy-on-write during the import, plus one growth step of the map, less
/// what the store already holds, and never less than one growth step.
pub(crate) fn estimate(rows: u64, existing: u64) -> Estimate {
    let store_bytes = rows.saturating_mul(BYTES_PER_ROW);
    let required_free = store_bytes
        .saturating_mul(REWRITE_FACTOR)
        .saturating_add(GROWTH_STEP)
        .saturating_sub(existing)
        .max(GROWTH_STEP);
    Estimate {
        store_bytes,
        required_free,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Space {
    Enough,
    NotEnough,
    Unknown,
}

pub(crate) fn space_verdict(required: Option<u64>, free: Option<u64>) -> Space {
    match (required, free) {
        (Some(r), Some(f)) if f >= r => Space::Enough,
        (Some(_), Some(_)) => Space::NotEnough,
        _ => Space::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Ready,
    ConfigProblem,
    V4Running,
    NotEnoughSpace,
    NotImported,
}

impl Verdict {
    pub(crate) fn exit_code(self) -> u8 {
        match self {
            Verdict::Ready => EXIT_READY,
            Verdict::ConfigProblem => EXIT_CONFIG,
            Verdict::V4Running => EXIT_V4_RUNNING,
            Verdict::NotEnoughSpace => EXIT_NO_SPACE,
            Verdict::NotImported => EXIT_NOT_IMPORTED,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Verdict::Ready => "ready",
            Verdict::ConfigProblem => "config_problem",
            Verdict::V4Running => "v4_running",
            Verdict::NotEnoughSpace => "not_enough_space",
            Verdict::NotImported => "not_imported",
        }
    }
}

/// The first thing in the way, in the order an operator has to deal with
/// them: the configuration, then v4, then disk space for the import, then
/// the import itself.
pub(crate) fn verdict(config_ok: bool, v4_running: bool, imported: bool, space: Space) -> Verdict {
    if !config_ok {
        Verdict::ConfigProblem
    } else if v4_running {
        Verdict::V4Running
    } else if imported {
        Verdict::Ready
    } else if space == Space::NotEnough {
        Verdict::NotEnoughSpace
    } else {
        Verdict::NotImported
    }
}

/// Bytes for people: `1.4 GiB`, `512.0 MiB`, `900 bytes`.
pub(crate) fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} bytes");
    }
    let mut v = bytes as f64 / 1024.0;
    let mut unit = UNITS[0];
    for u in &UNITS[1..] {
        if v < 1024.0 {
            break;
        }
        v /= 1024.0;
        unit = u;
    }
    format!("{v:.1} {unit}")
}

// ---- gathering facts -----------------------------------------------------

#[derive(Debug)]
enum ConfigState {
    Valid,
    Missing,
    Invalid(String),
}

#[derive(Debug)]
struct ConfigFacts {
    path: String,
    state: ConfigState,
    user: Option<String>,
    piddir: Option<String>,
    whois_port: u16,
    http_port: u16,
    database_url: Option<String>,
}

fn read_config(path: Option<&str>) -> ConfigFacts {
    let path = path.unwrap_or(config::CONFIG_PATH_DEFAULT).to_owned();
    let mut facts = ConfigFacts {
        path: path.clone(),
        state: ConfigState::Missing,
        user: None,
        piddir: None,
        whois_port: 43,
        http_port: 8000,
        database_url: None,
    };
    if !Path::new(&path).exists() {
        return facts;
    }
    // systemd creates the unit's piddir when irrd-ng starts, so it need
    // not exist yet.
    let is_dir = |d: &str| d.trim_end_matches('/') == UNIT_PIDDIR || Path::new(d).is_dir();
    match Configuration::load_with_fs(Some(&path), &is_dir) {
        Ok(cfg) => {
            let port = |name: &str, default: u16| {
                settings::int_setting(&cfg, name)
                    .and_then(|p| u16::try_from(p).ok())
                    .unwrap_or(default)
            };
            facts.state = ConfigState::Valid;
            facts.user = settings::str_setting(&cfg, "user").filter(|u| !u.is_empty());
            facts.piddir = settings::str_setting(&cfg, "piddir").filter(|p| !p.is_empty());
            facts.whois_port = port("server.whois.port", 43);
            facts.http_port = port("server.http.port", 8000);
            facts.database_url =
                settings::str_setting(&cfg, "database_url").filter(|u| !u.is_empty());
        }
        Err(e) => facts.state = ConfigState::Invalid(e.to_string()),
    }
    facts
}

#[derive(Debug, Clone)]
enum V4Evidence {
    Systemd,
    PidFile {
        path: String,
        pid: u32,
        command: String,
    },
    Port {
        port: u16,
        what: &'static str,
        owner: Option<(u32, String, ProcKind)>,
    },
}

impl V4Evidence {
    fn line(&self) -> String {
        match self {
            V4Evidence::Systemd => m::V4_SYSTEMD.to_owned(),
            V4Evidence::PidFile { path, pid, command } => m::v4_pidfile(path, *pid, command),
            V4Evidence::Port { port, what, owner } => match owner {
                Some((pid, cmd, ProcKind::V4)) => m::port_held_by_v4(*port, what, *pid, cmd),
                Some((pid, cmd, _)) => m::port_held_by_other(*port, what, *pid, cmd),
                None => m::port_held_unknown(*port, what),
            },
        }
    }

    fn json(&self) -> serde_json::Value {
        match self {
            V4Evidence::Systemd => json!({"kind": "systemd", "unit": "irrd.service"}),
            V4Evidence::PidFile { path, pid, command } => {
                json!({"kind": "pidfile", "path": path, "pid": pid, "command": command})
            }
            V4Evidence::Port { port, what, owner } => json!({
                "kind": "port",
                "port": port,
                "service": what,
                "pid": owner.as_ref().map(|o| o.0),
                "command": owner.as_ref().map(|o| o.1.clone()),
                "owner": match owner {
                    Some((_, _, ProcKind::V4)) => "irrd-v4",
                    Some(_) => "other",
                    None => "unknown",
                },
            }),
        }
    }
}

#[derive(Debug, Default)]
struct ProcessFacts {
    v4: Vec<V4Evidence>,
    ng_running: bool,
}

fn systemd_running() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

fn unit_active(unit: &str) -> bool {
    systemd_running()
        && std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", unit])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
}

/// `(exe, argv0 resolved, argv)` of a live process.
fn process(pid: u32) -> Option<(Option<String>, Option<String>, Vec<String>)> {
    let dir = PathBuf::from(format!("/proc/{pid}"));
    let cmdline = std::fs::read(dir.join("cmdline")).ok()?;
    let argv: Vec<String> = cmdline
        .split(|b| *b == 0)
        .filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    let exe = std::fs::read_link(dir.join("exe"))
        .ok()
        .map(|p| p.display().to_string());
    let argv0_target = argv
        .first()
        .filter(|a| a.starts_with('/'))
        .and_then(|a| std::fs::canonicalize(a).ok())
        .map(|p| p.display().to_string());
    Some((exe, argv0_target, argv))
}

fn describe(argv: &[String], exe: Option<&str>) -> String {
    if argv.is_empty() {
        exe.unwrap_or("?").to_owned()
    } else {
        argv.join(" ")
    }
}

/// A process [`classify`] cannot place, from the name the kernel keeps
/// for it (`/proc/<pid>/comm`, at most 15 bytes). v4's process titles set
/// that name as well as the command line, and it stays visible where the
/// command line does not show the title, for example under an emulator
/// such as qemu-user.
pub(crate) fn classify_comm(comm: &str) -> ProcKind {
    let comm = comm.trim_end();
    if comm.starts_with("irrd-") && !comm.starts_with("irrd-ng") {
        ProcKind::V4
    } else {
        ProcKind::Other
    }
}

fn classify_pid(pid: u32) -> Option<(ProcKind, String)> {
    let (exe, target, argv) = process(pid)?;
    let kind = classify(exe.as_deref(), target.as_deref(), &argv);
    if kind == ProcKind::Other
        && let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        && classify_comm(&comm) == ProcKind::V4
    {
        return Some((ProcKind::V4, comm.trim_end().to_owned()));
    }
    Some((kind, describe(&argv, exe.as_deref())))
}

/// The PIDs holding each of `inodes` open, from `/proc/*/fd`.
fn socket_owners(inodes: &HashSet<u64>) -> HashMap<u64, u32> {
    let mut out = HashMap::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in procs.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Some(inode) = std::fs::read_link(fd.path())
                .ok()
                .and_then(|l| socket_inode(&l.to_string_lossy()))
                && inodes.contains(&inode)
            {
                out.entry(inode).or_insert(pid);
            }
        }
        if out.len() == inodes.len() {
            break;
        }
    }
    out
}

fn check_processes(cfg: &ConfigFacts) -> ProcessFacts {
    let mut facts = ProcessFacts {
        ng_running: unit_active("irrd-ng.service"),
        ..ProcessFacts::default()
    };
    if unit_active("irrd.service") {
        facts.v4.push(V4Evidence::Systemd);
    }

    let piddir = cfg.piddir.as_deref().unwrap_or(UNIT_PIDDIR);
    let pidfile = Path::new(piddir).join("irrd.pid");
    if let Some(pid) = std::fs::read_to_string(&pidfile)
        .ok()
        .as_deref()
        .and_then(parse_pidfile)
    {
        match classify_pid(pid) {
            Some((ProcKind::V4, command)) => facts.v4.push(V4Evidence::PidFile {
                path: pidfile.display().to_string(),
                pid,
                command,
            }),
            Some((ProcKind::IrrdNg, _)) => facts.ng_running = true,
            // A stale PID file, or the PID now belongs to something else.
            _ => {}
        }
    }

    let mut listening = Vec::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(table) {
            listening.extend(parse_listening(&text));
        }
    }
    let wanted = [(cfg.whois_port, "whois"), (cfg.http_port, "HTTP")];
    let mut ports: Vec<(u16, &'static str, Vec<u64>)> = Vec::new();
    for (port, what) in wanted {
        if ports.iter().any(|(p, _, _)| *p == port) {
            continue;
        }
        let inodes: Vec<u64> = listening
            .iter()
            .filter(|(p, _)| *p == port)
            .map(|(_, i)| *i)
            .collect();
        if !inodes.is_empty() {
            ports.push((port, what, inodes));
        }
    }
    let all: HashSet<u64> = ports.iter().flat_map(|(_, _, i)| i.clone()).collect();
    let owners = if all.is_empty() {
        HashMap::new()
    } else {
        socket_owners(&all)
    };
    for (port, what, inodes) in ports {
        let owner = inodes
            .iter()
            .find_map(|i| owners.get(i))
            .and_then(|pid| classify_pid(*pid).map(|(k, c)| (*pid, c, k)));
        match owner {
            Some((_, _, ProcKind::IrrdNg)) => facts.ng_running = true,
            owner => facts.v4.push(V4Evidence::Port { port, what, owner }),
        }
    }
    facts
}

#[derive(Debug)]
enum StoreState {
    Absent,
    Empty,
    Imported { sources: usize, objects: u64 },
    NeedsUpgrade,
    Incomplete,
    Unusable(String),
}

impl StoreState {
    fn imported(&self) -> bool {
        matches!(self, StoreState::Imported { .. } | StoreState::NeedsUpgrade)
    }

    fn name(&self) -> &'static str {
        match self {
            StoreState::Absent => "absent",
            StoreState::Empty => "empty",
            StoreState::Imported { .. } => "imported",
            StoreState::NeedsUpgrade => "imported_needs_upgrade",
            StoreState::Incomplete => "incomplete",
            StoreState::Unusable(_) => "unusable",
        }
    }
}

#[derive(Debug)]
struct StoreFacts {
    path: PathBuf,
    state: StoreState,
    /// Bytes `data.mdb` takes on disk.
    disk_bytes: u64,
    owner_uid: Option<u32>,
}

fn check_store(path: &Path) -> StoreFacts {
    use std::os::unix::fs::MetadataExt as _;
    let owner_uid = std::fs::metadata(path).ok().map(|m| m.uid());
    let data = store::env::data_file(path);
    let Ok(meta) = std::fs::metadata(&data) else {
        return StoreFacts {
            path: path.to_owned(),
            state: StoreState::Absent,
            disk_bytes: 0,
            owner_uid,
        };
    };
    let disk_bytes = meta.blocks().saturating_mul(512);
    let lock = path.join("lock.mdb");
    let lock_existed = lock.exists();
    let options = StoreOptions {
        read_only: true,
        ..StoreOptions::new(path)
    };
    let state = match Store::open(&options, store::StoreSettings::default()) {
        Ok(st) => match st.read().and_then(|r| {
            let v = r.view();
            Ok((v.database_statuses()?.len(), v.object_count()?))
        }) {
            Ok((0, 0)) => StoreState::Empty,
            Ok((sources, objects)) => StoreState::Imported { sources, objects },
            Err(e) => StoreState::Unusable(e.to_string()),
        },
        Err(StoreError::NotInitialised(_)) => StoreState::Empty,
        Err(StoreError::LoadIncomplete { .. }) => StoreState::Incomplete,
        Err(StoreError::SchemaTooOld { .. }) => StoreState::NeedsUpgrade,
        Err(e) => StoreState::Unusable(e.to_string()),
    };
    // A read-only LMDB open creates lock.mdb if it is missing. Hand it to
    // whoever owns the data, so the daemon is not locked out by root.
    if !lock_existed
        && let Ok(l) = std::fs::metadata(&lock)
        && (l.uid(), l.gid()) != (meta.uid(), meta.gid())
    {
        let _ = std::os::unix::fs::chown(&lock, Some(meta.uid()), Some(meta.gid()));
    }
    StoreFacts {
        path: path.to_owned(),
        state,
        disk_bytes,
        owner_uid,
    }
}

/// Free bytes for unprivileged use on the filesystem holding `path`, or
/// its nearest existing parent: (that directory, bytes).
fn free_space(path: &Path) -> (PathBuf, Result<u64, String>) {
    let mut dir = path.to_owned();
    while !dir.exists() {
        match dir.parent() {
            Some(p) => dir = p.to_owned(),
            None => break,
        }
    }
    #[allow(clippy::unnecessary_cast)]
    let free = nix::sys::statvfs::statvfs(&dir)
        .map(|s| (s.blocks_available() as u64).saturating_mul(s.fragment_size() as u64))
        .map_err(|e| e.desc().to_owned());
    (dir, free)
}

#[derive(Debug)]
enum DbFacts {
    SkippedImported,
    SkippedNoConfig,
    NoUrl,
    Size {
        target: String,
        size: import_v4::SourceSize,
    },
    Unreachable {
        target: String,
        error: String,
    },
}

fn check_database(url: &str) -> DbFacts {
    let target = import_v4::describe(url);
    match import_v4::probe_size(url, CONNECT_TIMEOUT, STATEMENT_TIMEOUT) {
        Ok(size) => DbFacts::Size { target, size },
        Err(e) => {
            let mut error = e.to_string();
            let mut source = std::error::Error::source(&e);
            while let Some(s) = source {
                error.push_str(": ");
                error.push_str(&s.to_string());
                source = s.source();
            }
            DbFacts::Unreachable { target, error }
        }
    }
}

// ---- the report ----------------------------------------------------------

#[derive(Debug)]
struct Report {
    config: ConfigFacts,
    procs: ProcessFacts,
    store: StoreFacts,
    db: DbFacts,
    fs_dir: PathBuf,
    free: Result<u64, String>,
    estimate: Option<Estimate>,
    space: Space,
    notes: Vec<String>,
    verdict: Verdict,
}

fn gather(config_path: Option<&str>) -> Report {
    let config = read_config(config_path);
    let procs = check_processes(&config);
    let store_path =
        std::path::absolute(settings::store_path()).unwrap_or_else(|_| settings::store_path());
    let store = check_store(&store_path);
    let db = match (&config.state, &config.database_url) {
        _ if store.state.imported() => DbFacts::SkippedImported,
        (ConfigState::Valid, Some(url)) => check_database(url),
        (ConfigState::Valid, None) => DbFacts::NoUrl,
        _ => DbFacts::SkippedNoConfig,
    };
    let (fs_dir, free) = free_space(&store_path);
    let estimate = match &db {
        DbFacts::Size { size, .. } => Some(estimate(size.rows(), store.disk_bytes)),
        _ => None,
    };
    let space = space_verdict(
        estimate.map(|e| e.required_free),
        free.as_ref().ok().copied(),
    );

    let mut notes = Vec::new();
    if config.path != config::CONFIG_PATH_DEFAULT {
        notes.push(m::note_config_path(&config.path));
    }
    if let ConfigState::Valid = config.state {
        if let Some(piddir) = &config.piddir
            && piddir.trim_end_matches('/') != UNIT_PIDDIR
        {
            notes.push(m::note_piddir(piddir));
        }
        match &config.user {
            None => notes.push(m::NOTE_NO_USER_SETTING.to_owned()),
            Some(user) => match nix::unistd::User::from_name(user) {
                Ok(Some(u)) => {
                    if let Some(uid) = store.owner_uid
                        && uid != u.uid.as_raw()
                    {
                        let owner = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
                            .ok()
                            .flatten()
                            .map_or_else(|| format!("uid {uid}"), |o| o.name);
                        notes.push(m::note_store_owner(
                            &store.path.display().to_string(),
                            &owner,
                            user,
                        ));
                    }
                }
                _ => notes.push(m::note_no_user(user)),
            },
        }
    }

    let verdict = verdict(
        matches!(config.state, ConfigState::Valid),
        !procs.v4.is_empty(),
        store.state.imported(),
        space,
    );
    Report {
        config,
        procs,
        store,
        db,
        fs_dir,
        free,
        estimate,
        space,
        notes,
        verdict,
    }
}

impl Report {
    fn user(&self) -> &str {
        self.config.user.as_deref().unwrap_or("irrd")
    }

    fn pidfile(&self) -> String {
        format!(
            "{}/irrd.pid",
            self.config
                .piddir
                .as_deref()
                .unwrap_or(UNIT_PIDDIR)
                .trim_end_matches('/')
        )
    }

    fn text(&self) -> String {
        let mut out = String::new();
        out.push_str(m::TITLE);
        out.push_str("\n\n");

        let config = match &self.config.state {
            ConfigState::Valid => vec![m::config_valid(&self.config.path)],
            ConfigState::Missing => vec![m::config_missing(&self.config.path)],
            ConfigState::Invalid(e) => {
                let mut v = vec![m::config_invalid(&self.config.path)];
                v.extend(e.lines().map(|l| format!("  {l}")));
                v
            }
        };
        m::field(&mut out, m::L_CONFIG, &config);

        let mut v4 = vec![if self.procs.v4.is_empty() {
            m::V4_NOT_RUNNING.to_owned()
        } else {
            m::V4_RUNNING.to_owned()
        }];
        v4.extend(self.procs.v4.iter().map(V4Evidence::line));
        m::field(&mut out, m::L_V4, &v4);
        m::field(
            &mut out,
            m::L_NG,
            &[if self.procs.ng_running {
                m::NG_RUNNING
            } else {
                m::NG_NOT_RUNNING
            }
            .to_owned()],
        );

        let path = self.store.path.display().to_string();
        let store = match &self.store.state {
            StoreState::Absent => m::store_absent(&path),
            StoreState::Empty => m::store_empty(&path),
            StoreState::Imported { sources, objects } => {
                m::store_imported(&path, *sources, *objects, &human(self.store.disk_bytes))
            }
            StoreState::NeedsUpgrade => {
                m::store_needs_upgrade(&path, &human(self.store.disk_bytes))
            }
            StoreState::Incomplete => m::store_incomplete(&path),
            StoreState::Unusable(why) => m::store_unusable(&path, why),
        };
        m::field(&mut out, m::L_STORE, &[store]);

        let masked = self
            .config
            .database_url
            .as_deref()
            .map(import_v4::mask_password);
        let db = match &self.db {
            DbFacts::SkippedImported => vec![m::DB_SKIPPED_IMPORTED.to_owned()],
            DbFacts::SkippedNoConfig => vec![m::DB_SKIPPED_NO_CONFIG.to_owned()],
            DbFacts::NoUrl => vec![m::DB_NO_URL.to_owned()],
            DbFacts::Size { target, size } => m::db_size(
                target,
                size.database_bytes.map(human).as_deref(),
                size.rpsl_objects,
                size.journal,
                size.roas,
                size.approximate,
            ),
            DbFacts::Unreachable { target, error } => {
                m::db_unreachable(target, error, masked.as_deref().unwrap_or_default())
            }
        };
        m::field(&mut out, m::L_DB, &db);

        let fs_dir = self.fs_dir.display().to_string();
        let space = match (&self.free, self.estimate) {
            (Err(e), _) => vec![m::space_unreadable(&fs_dir, e)],
            (Ok(free), _) if self.store.state.imported() => vec![m::space_imported(
                &human(self.store.disk_bytes),
                &fs_dir,
                &human(*free),
            )],
            (Ok(free), Some(est)) => m::space_known(
                &human(est.store_bytes),
                &human(est.required_free),
                &fs_dir,
                &human(*free),
                self.space == Space::Enough,
            ),
            (Ok(free), None) => m::space_unknown(&fs_dir, &human(*free)),
        };
        m::field(&mut out, m::L_SPACE, &space);
        if !self.notes.is_empty() {
            let notes: Vec<String> = self.notes.iter().map(|n| format!("- {n}")).collect();
            m::field(&mut out, m::L_NOTES, &notes);
        }

        out.push('\n');
        out.push_str(match self.verdict {
            Verdict::Ready if self.procs.ng_running => m::RESULT_RUNNING,
            Verdict::Ready => m::RESULT_READY,
            Verdict::ConfigProblem => m::RESULT_CONFIG,
            Verdict::V4Running => m::RESULT_V4,
            Verdict::NotEnoughSpace => m::RESULT_SPACE,
            Verdict::NotImported => m::RESULT_NOT_IMPORTED,
        });
        out.push('\n');
        let steps = self.steps();
        if !steps.is_empty() {
            out.push('\n');
            out.push_str(m::NEXT);
            out.push('\n');
            for (i, (head, body)) in steps.iter().enumerate() {
                out.push_str(&format!("\n{}. {head}\n", i + 1));
                for line in body {
                    out.push_str(&format!("     {line}\n"));
                }
            }
            out.push('\n');
            out.push_str(m::PG_REDIS);
            out.push('\n');
            out.push_str(m::RUNBOOK);
            out.push('\n');
        }
        out
    }

    /// The steps left, each a heading and its indented lines.
    fn steps(&self) -> Vec<(String, Vec<String>)> {
        let mut steps = Vec::new();
        match self.config.state {
            ConfigState::Missing => {
                steps.push((m::step_config_missing(&self.config.path), Vec::new()));
            }
            ConfigState::Invalid(_) => {
                steps.push((m::step_config_invalid(&self.config.path), Vec::new()));
            }
            ConfigState::Valid => {}
        }
        if self.procs.ng_running && self.procs.v4.is_empty() {
            return steps;
        }

        if !self.procs.v4.is_empty() {
            let mut body: Vec<String> = Vec::new();
            let v4_seen = self.procs.v4.iter().any(|e| {
                matches!(
                    e,
                    V4Evidence::Systemd
                        | V4Evidence::PidFile { .. }
                        | V4Evidence::Port {
                            owner: Some((_, _, ProcKind::V4)),
                            ..
                        }
                )
            });
            if v4_seen {
                body.extend(m::STOP_V4_SYSTEMD.iter().map(|s| (*s).to_owned()));
                body.push(m::stop_v4_no_systemd(&self.pidfile()));
                body.push(m::stop_v4_pidfile(&self.pidfile()));
            }
            for e in &self.procs.v4 {
                if let V4Evidence::Port {
                    port,
                    owner: None | Some((_, _, ProcKind::Other | ProcKind::IrrdNg)),
                    ..
                } = e
                {
                    body.push(m::stop_other(*port));
                }
            }
            if !self.store.state.imported() {
                body.push(m::KEEP_PG.to_owned());
            }
            steps.push((m::STEP_STOP_V4.to_owned(), body));
        }

        if !self.store.state.imported() {
            let store = self.store.path.display().to_string();
            let mut body = match &self.config.database_url {
                Some(url) => {
                    let masked = import_v4::mask_password(url);
                    vec![
                        m::import_command(self.user(), &store, &masked),
                        m::import_note(import_v4::MASK, masked != *url),
                    ]
                }
                None => vec![
                    m::import_command_no_url(self.user(), &store),
                    m::IMPORT_URL_NOTE.to_owned(),
                ],
            };
            if let (Some(est), Ok(free)) = (self.estimate, &self.free) {
                body.push(m::import_space(
                    &human(est.required_free),
                    &human(*free),
                    self.space == Space::Enough,
                ));
            }
            body.push(m::NEW_INSTALL.to_owned());
            steps.push((m::STEP_IMPORT.to_owned(), body));
        }

        steps.push((m::STEP_START.to_owned(), vec![m::START_COMMAND.to_owned()]));
        steps.push((
            m::STEP_CHECK.to_owned(),
            m::check_commands(self.config.whois_port).to_vec(),
        ));
        steps.push((
            m::STEP_ROLLBACK.to_owned(),
            m::ROLLBACK_COMMANDS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        ));
        steps
    }

    fn json(&self) -> serde_json::Value {
        let (config_status, config_error) = match &self.config.state {
            ConfigState::Valid => ("valid", None),
            ConfigState::Missing => ("missing", None),
            ConfigState::Invalid(e) => ("invalid", Some(e.clone())),
        };
        let db = match &self.db {
            DbFacts::SkippedImported => json!({"checked": false, "reason": "store_imported"}),
            DbFacts::SkippedNoConfig => json!({"checked": false, "reason": "no_config"}),
            DbFacts::NoUrl => json!({"checked": false, "reason": "no_database_url"}),
            DbFacts::Size { target, size } => json!({
                "checked": true,
                "reachable": true,
                "target": target,
                "database_bytes": size.database_bytes,
                "rpsl_objects": size.rpsl_objects,
                "journal_entries": size.journal,
                "roas": size.roas,
                "approximate": size.approximate,
            }),
            DbFacts::Unreachable { target, error } => json!({
                "checked": true,
                "reachable": false,
                "target": target,
                "error": error,
            }),
        };
        let (sources, objects) = match &self.store.state {
            StoreState::Imported { sources, objects } => (Some(*sources), Some(*objects)),
            _ => (None, None),
        };
        json!({
            "verdict": self.verdict.name(),
            "exit_code": self.verdict.exit_code(),
            "config": {
                "path": self.config.path,
                "status": config_status,
                "error": config_error,
                "user": self.config.user,
                "piddir": self.config.piddir,
                "whois_port": self.config.whois_port,
                "http_port": self.config.http_port,
                "database_url": self.config.database_url.as_deref().map(import_v4::mask_password),
            },
            "irrd_v4": {
                "running": !self.procs.v4.is_empty(),
                "evidence": self.procs.v4.iter().map(V4Evidence::json).collect::<Vec<_>>(),
            },
            "irrd_ng": {"running": self.procs.ng_running},
            "store": {
                "path": self.store.path,
                "state": self.store.state.name(),
                "imported": self.store.state.imported(),
                "error": match &self.store.state {
                    StoreState::Unusable(e) => Some(e.clone()),
                    _ => None,
                },
                "disk_bytes": self.store.disk_bytes,
                "sources": sources,
                "objects": objects,
            },
            "v4_database": db,
            "space": {
                "filesystem_path": self.fs_dir,
                "free_bytes": self.free.as_ref().ok(),
                "error": self.free.as_ref().err(),
                "estimated_store_bytes": self.estimate.map(|e| e.store_bytes),
                "required_free_bytes": self.estimate.map(|e| e.required_free),
                "verdict": match self.space {
                    Space::Enough => "enough",
                    Space::NotEnough => "not_enough",
                    Space::Unknown => "unknown",
                },
            },
            "notes": self.notes,
        })
    }
}

pub(crate) fn run(args: &[OsString]) -> ExitCode {
    let args = match parse(args) {
        Ok(Some(a)) => a,
        Ok(None) => {
            println!("{}", m::USAGE);
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("{}", m::USAGE);
            eprintln!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let report = gather(args.config.as_deref());
    match args.output {
        Output::Text => print!("{}", report.text()),
        Output::Json => println!("{}", report.json()),
        Output::Quiet => {}
    }
    ExitCode::from(report.verdict.exit_code())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn irrd_ng_is_recognised_by_exe_or_name() {
        let k = classify(
            Some("/usr/bin/irrd-ng"),
            None,
            &argv(&["/usr/bin/irrd", "--foreground"]),
        );
        assert_eq!(k, ProcKind::IrrdNg);
        // After an upgrade the old binary shows as deleted.
        let k = classify(Some("/usr/bin/irrd-ng (deleted)"), None, &argv(&["irrd"]));
        assert_eq!(k, ProcKind::IrrdNg);
        // exe unreadable (not root): argv[0] resolves through the symlink.
        let k = classify(None, Some("/usr/bin/irrd-ng"), &argv(&["/usr/bin/irrd"]));
        assert_eq!(k, ProcKind::IrrdNg);
        // Under qemu-user the exe is the emulator.
        let k = classify(
            Some("/usr/bin/qemu-aarch64-static"),
            None,
            &argv(&[
                "/usr/bin/qemu-aarch64-static",
                "/usr/bin/irrd-ng",
                "migrate-check",
            ]),
        );
        assert_eq!(k, ProcKind::IrrdNg);
    }

    #[test]
    fn irrd_v4_is_recognised() {
        // The main process: Python running the irrd console script.
        let k = classify(
            Some("/usr/bin/python3.11"),
            None,
            &argv(&[
                "/home/irrd/irrd-venv/bin/python3",
                "/home/irrd/irrd-venv/bin/irrd",
                "--config",
                "/etc/irrd.yaml",
            ]),
        );
        assert_eq!(k, ProcKind::V4);
        // Children renamed with setproctitle.
        for title in [
            "irrd-whois-server-listener",
            "irrd-whois-worker-192.0.2.1:4242",
            "irrd-http-server-listener",
            "irrd-preload-store-manager",
        ] {
            assert_eq!(
                classify(Some("/usr/bin/python3.11"), None, &argv(&[title])),
                ProcKind::V4,
                "{title}"
            );
        }
        // v4 started as `irrd` from a venv when exe cannot be read.
        assert_eq!(
            classify(
                None,
                Some("/home/irrd/venv/bin/irrd"),
                &argv(&["/home/irrd/venv/bin/irrd"])
            ),
            ProcKind::V4
        );
    }

    #[test]
    fn other_programs_are_neither() {
        for (exe, a) in [
            ("/usr/sbin/nginx", vec!["nginx: master process"]),
            (
                "/usr/bin/python3.12",
                vec!["/usr/bin/python3", "-m", "http.server"],
            ),
            ("/usr/sbin/sshd", vec!["sshd: /usr/sbin/sshd -D"]),
        ] {
            assert_eq!(
                classify(Some(exe), None, &argv(&a)),
                ProcKind::Other,
                "{exe}"
            );
        }
    }

    #[test]
    fn proc_net_tcp_listeners() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000:002B 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31337 1 0000000000000000 100 0 0 10 0\n\
   1: 0100007F:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000   998        0 4242 1 0000000000000000 100 0 0 10 0\n\
   2: 0100007F:B5C2 0100007F:002B 01 00000000:00000000 00:00000000 00000000  1000        0 999 1 0000000000000000 20 4 30 10 -1\n";
        assert_eq!(parse_listening(tcp), vec![(43, 31337), (8000, 4242)]);
        let tcp6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000000000000000000000000000:002B 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5555 1 0000000000000000 100 0 0 10 0\n";
        assert_eq!(parse_listening(tcp6), vec![(43, 5555)]);
        assert!(parse_listening("header only\n").is_empty());
        assert!(parse_listening("").is_empty());
    }

    #[test]
    fn fd_links_and_pidfiles() {
        assert_eq!(socket_inode("socket:[31337]"), Some(31337));
        assert_eq!(socket_inode("pipe:[31337]"), None);
        assert_eq!(socket_inode("/dev/null"), None);
        assert_eq!(socket_inode("socket:[x]"), None);
        assert_eq!(parse_pidfile("1234\n"), Some(1234));
        assert_eq!(parse_pidfile(" 77 "), Some(77));
        assert_eq!(parse_pidfile(""), None);
        assert_eq!(parse_pidfile("0\n"), None);
        assert_eq!(parse_pidfile("abc"), None);
    }

    #[test]
    fn size_estimates_follow_the_measurements() {
        // Full RADB, 1.37 million objects: measured 1,839 MB.
        let radb = estimate(1_370_000, 0);
        assert!(radb.store_bytes >= 1_839_000_000, "{}", radb.store_bytes);
        assert!(radb.store_bytes < 2_200_000_000, "{}", radb.store_bytes);
        // 6,444,813 rows: measured 7.7 GB.
        let prod = estimate(6_444_813, 0);
        assert!(prod.store_bytes >= 7_700_000_000, "{}", prod.store_bytes);
        assert!(prod.store_bytes < 10_000_000_000, "{}", prod.store_bytes);
        assert_eq!(prod.required_free, prod.store_bytes * 2 + GROWTH_STEP);
        // An existing store counts towards the space, down to one step.
        let again = estimate(6_444_813, 8_000_000_000);
        assert_eq!(
            again.required_free,
            prod.store_bytes * 2 + GROWTH_STEP - 8_000_000_000
        );
        assert_eq!(estimate(10, 50 * GROWTH_STEP).required_free, GROWTH_STEP);
        assert_eq!(estimate(0, 0).required_free, GROWTH_STEP);
        assert_eq!(estimate(u64::MAX, 0).store_bytes, u64::MAX);
    }

    #[test]
    fn space_verdicts() {
        assert_eq!(space_verdict(Some(10), Some(10)), Space::Enough);
        assert_eq!(space_verdict(Some(10), Some(9)), Space::NotEnough);
        assert_eq!(space_verdict(None, Some(9)), Space::Unknown);
        assert_eq!(space_verdict(Some(10), None), Space::Unknown);
    }

    #[test]
    fn verdict_order_and_exit_codes() {
        use Space::*;
        assert_eq!(verdict(true, false, true, Unknown), Verdict::Ready);
        assert_eq!(verdict(true, false, true, NotEnough), Verdict::Ready);
        assert_eq!(
            verdict(false, true, false, NotEnough),
            Verdict::ConfigProblem
        );
        assert_eq!(verdict(true, true, true, Enough), Verdict::V4Running);
        assert_eq!(verdict(true, true, false, NotEnough), Verdict::V4Running);
        assert_eq!(
            verdict(true, false, false, NotEnough),
            Verdict::NotEnoughSpace
        );
        assert_eq!(verdict(true, false, false, Enough), Verdict::NotImported);
        assert_eq!(verdict(true, false, false, Unknown), Verdict::NotImported);
        let codes: HashSet<u8> = [
            Verdict::Ready,
            Verdict::ConfigProblem,
            Verdict::V4Running,
            Verdict::NotEnoughSpace,
            Verdict::NotImported,
        ]
        .iter()
        .map(|v| v.exit_code())
        .collect();
        assert_eq!(codes.len(), 5);
        assert!(!codes.contains(&EXIT_USAGE) && !codes.contains(&1));
        assert_eq!(Verdict::Ready.exit_code(), 0);
    }

    #[test]
    fn grouped_counts() {
        assert_eq!(m::grouped(0), "0");
        assert_eq!(m::grouped(999), "999");
        assert_eq!(m::grouped(1000), "1,000");
        assert_eq!(m::grouped(6_444_813), "6,444,813");
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human(900), "900 bytes");
        assert_eq!(human(1536), "1.5 KiB");
        assert_eq!(human(1_839_000_000), "1.7 GiB");
        assert_eq!(human(3 << 40), "3.0 TiB");
    }

    #[test]
    fn arguments() {
        let os = |a: &[&str]| -> Vec<OsString> { a.iter().map(OsString::from).collect() };
        let a = parse(&os(&["migrate-check", "--config", "/x.yaml", "--json"]))
            .unwrap()
            .unwrap();
        assert_eq!(a.config.as_deref(), Some("/x.yaml"));
        assert_eq!(a.output, Output::Json);
        let a = parse(&os(&["migrate-check", "--config=/y", "-q"]))
            .unwrap()
            .unwrap();
        assert_eq!(a.config.as_deref(), Some("/y"));
        assert_eq!(a.output, Output::Quiet);
        assert!(parse(&os(&["migrate-check", "--help"])).unwrap().is_none());
        assert!(parse(&os(&["migrate-check", "--quiet", "--json"])).is_err());
        assert!(parse(&os(&["migrate-check", "--config"])).is_err());
        assert!(parse(&os(&["migrate-check", "--bogus"])).is_err());
    }

    /// The whole report on a host with a valid configuration, no store and
    /// an unreachable database: not imported, with the import command and
    /// a masked password.
    #[test]
    fn report_for_a_fresh_host() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("irrd.yaml");
        std::fs::write(
            &cfg,
            "irrd:\n  database_url: postgresql://irrd:hunter2@127.0.0.1:1/irrd\n  redis_url: redis://x\n  piddir: /run/irrd\n  user: root\n  group: irrd\n  email:\n    from: a@example.net\n    smtp: localhost\n  auth:\n    gnupg_keyring: /tmp\n  server:\n    whois:\n      port: 4343\n    http:\n      url: http://localhost/\n      port: 4380\n",
        )
        .unwrap();
        let facts = read_config(cfg.to_str());
        assert!(
            matches!(facts.state, ConfigState::Valid),
            "{:?}",
            facts.state
        );
        assert_eq!((facts.whois_port, facts.http_port), (4343, 4380));
        let store = check_store(&dir.path().join("store"));
        assert!(matches!(store.state, StoreState::Absent));
        let db = check_database(facts.database_url.as_deref().unwrap());
        assert!(matches!(db, DbFacts::Unreachable { .. }), "{db:?}");
        let (fs_dir, free) = free_space(&store.path);
        let report = Report {
            config: facts,
            procs: ProcessFacts::default(),
            store,
            db,
            fs_dir,
            free,
            estimate: None,
            space: Space::Unknown,
            notes: Vec::new(),
            verdict: Verdict::NotImported,
        };
        let text = report.text();
        assert!(
            text.contains("Result: NOT READY, because the v4 database has not been imported yet.")
        );
        assert!(
            text.contains(
                "irrd-ng import --from-postgres 'postgresql://irrd:****@127.0.0.1:1/irrd'"
            )
        );
        assert!(text.contains("whois -h localhost -p 4343 '!v'"));
        assert!(!text.contains("hunter2"));
        let json = report.json().to_string();
        assert!(!json.contains("hunter2"));
        assert!(json.contains("\"verdict\":\"not_imported\""));
    }

    #[test]
    fn missing_and_invalid_configurations() {
        let dir = tempfile::tempdir().unwrap();
        let missing = read_config(dir.path().join("none.yaml").to_str());
        assert!(matches!(missing.state, ConfigState::Missing));
        let bad = dir.path().join("bad.yaml");
        std::fs::write(&bad, "irrd:\n  piddir: /nonexistent\n").unwrap();
        let invalid = read_config(bad.to_str());
        assert!(
            matches!(invalid.state, ConfigState::Invalid(_)),
            "{:?}",
            invalid.state
        );
    }

    /// A store with data is imported; an interrupted load is not.
    #[test]
    fn store_states() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store");
        let mut options = StoreOptions::new(&path);
        options.initial_map_size = 64 << 20;
        options.growth_step = 64 << 20;
        {
            let st = Store::open(&options, store::StoreSettings::default()).unwrap();
            drop(st);
        }
        assert!(matches!(check_store(&path).state, StoreState::Empty));
        {
            let st = Store::open(&options, store::StoreSettings::default()).unwrap();
            let load = st.begin_whole_store_load("<all>").unwrap();
            load.abandon_for_tests();
        }
        assert!(matches!(check_store(&path).state, StoreState::Incomplete));
    }

    #[test]
    fn kernel_name_identifies_v4_titles() {
        assert_eq!(classify_comm("irrd-whois-serv\n"), ProcKind::V4);
        assert_eq!(classify_comm("irrd-http-serve\n"), ProcKind::V4);
        assert_eq!(classify_comm("irrd-ng\n"), ProcKind::Other);
        assert_eq!(classify_comm("perl\n"), ProcKind::Other);
        assert_eq!(classify_comm("nginx\n"), ProcKind::Other);
    }
}
