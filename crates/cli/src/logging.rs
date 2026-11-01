//! v4's logging, which is Python's `logging` configured by
//! `irrd/conf/__init__.py`:
//!
//! - by default the `LOGGING` dictionary there: one stream handler on
//!   stderr with the `verbose` formatter,
//!   `%(asctime)s irrd[%(process)d]: [%(name)s#%(levelname)s] %(message)s`,
//!   times in UTC;
//! - with `log.logfile_path`, a `WatchedFileHandler` on that file instead,
//!   which reopens the file when log rotation moves it;
//! - with `log.logging_config_path`, the operator's own `dictConfig`
//!   ([`crate::pylogconf`]);
//! - and in every case the root logger's level set from `log.level`
//!   (default `INFO`) when the configuration is committed: at startup and
//!   again on every SIGHUP.
//!
//! The logger name is the tracing target, so code logs under v4's module
//! names (`irrd.mirroring.parsers`), and loggers form v4's dotted
//! hierarchy for levels, handlers and propagation. An `error!` event with
//! a `critical` field is `CRITICAL`, which tracing lacks. Events from the
//! libraries underneath (HTTP, DNS, FTP), which v4 does not have, are
//! dropped.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;

use crate::pylogconf::{self, HandlerConfig, HandlerKind, LogConfig, LoggerConfig};

/// v4's `verbose` format.
pub(crate) const VERBOSE: &str =
    "%(asctime)s irrd[%(process)d]: [%(name)s#%(levelname)s] %(message)s";

/// Log target for irrd-ng's own notices about logging.
const LOG_TARGET: &str = "irrd_ng.logging";

// ---------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------

/// `YYYY-MM-DD HH:MM:SS,mmm` in UTC, as Python's `asctime` with
/// `converter = time.gmtime`.
pub(crate) fn asctime(now: store::Timestamp) -> String {
    let s = now.to_string();
    // 2026-10-31T01:02:03.123456+00:00
    format!("{} {},{}", &s[0..10], &s[11..19], &s[20..23])
}

/// `time.strftime(datefmt, time.gmtime(t))` for the common directives.
fn strftime(fmt: &str, now: store::Timestamp) -> String {
    const DAYS: [&str; 7] = [
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
    ];
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let s = now.to_string();
    let num = |a: usize, b: usize| s[a..b].parse::<u32>().unwrap_or(0);
    let (year, month, day) = (num(0, 4), num(5, 7), num(8, 10));
    let (hour, min, sec) = (num(11, 13), num(14, 16), num(17, 19));
    let days_since_epoch = now.unix_seconds().div_euclid(86_400);
    // 1970-01-01 was a Thursday (index 3 from Monday).
    let weekday = (days_since_epoch + 3).rem_euclid(7) as usize;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let cumulative = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let yday =
        cumulative[(month as usize).saturating_sub(1).min(11)] + day + u32::from(leap && month > 2);
    let mut out = String::new();
    let mut chars = fmt.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('Y') => out.push_str(&format!("{year:04}")),
            Some('y') => out.push_str(&format!("{:02}", year % 100)),
            Some('m') => out.push_str(&format!("{month:02}")),
            Some('d') => out.push_str(&format!("{day:02}")),
            Some('H') => out.push_str(&format!("{hour:02}")),
            Some('I') => out.push_str(&format!("{:02}", (hour + 11) % 12 + 1)),
            Some('M') => out.push_str(&format!("{min:02}")),
            Some('S') => out.push_str(&format!("{sec:02}")),
            Some('p') => out.push_str(if hour < 12 { "AM" } else { "PM" }),
            Some('j') => out.push_str(&format!("{yday:03}")),
            Some('a') => out.push_str(&DAYS[weekday][..3]),
            Some('A') => out.push_str(DAYS[weekday]),
            Some('b') => out.push_str(&MONTHS[(month as usize).saturating_sub(1) % 12][..3]),
            Some('B') => out.push_str(MONTHS[(month as usize).saturating_sub(1) % 12]),
            Some('Z') => out.push_str("UTC"),
            Some('z') => out.push_str("+0000"),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

/// One log record, as Python's `LogRecord` presents it to a formatter.
pub(crate) struct Record<'a> {
    pub(crate) name: &'a str,
    pub(crate) levelno: u8,
    pub(crate) message: &'a str,
    pub(crate) time: store::Timestamp,
}

pub(crate) fn level_name(levelno: u8) -> &'static str {
    match levelno {
        50.. => "CRITICAL",
        40..=49 => "ERROR",
        30..=39 => "WARNING",
        20..=29 => "INFO",
        _ => "DEBUG",
    }
}

/// A `%`-style format string, as Python's `logging.Formatter` applies it.
#[derive(Debug, Clone)]
pub(crate) struct Formatter {
    format: String,
    datefmt: Option<String>,
}

impl Formatter {
    pub(crate) fn new(format: &str, datefmt: Option<&str>) -> Self {
        Formatter {
            format: format.to_owned(),
            datefmt: datefmt.map(str::to_owned),
        }
    }

    fn field(&self, key: &str, r: &Record<'_>) -> Option<FieldValue> {
        let micros = r.time.0;
        Some(match key {
            "message" => FieldValue::Str(r.message.to_owned()),
            "name" => FieldValue::Str(r.name.to_owned()),
            "levelname" => FieldValue::Str(level_name(r.levelno).to_owned()),
            "levelno" => FieldValue::Int(i64::from(r.levelno)),
            "asctime" => FieldValue::Str(match &self.datefmt {
                Some(f) => strftime(f, r.time),
                None => asctime(r.time),
            }),
            "process" => FieldValue::Int(i64::from(std::process::id())),
            "processName" => FieldValue::Str("MainProcess".into()),
            "thread" => FieldValue::Int(0),
            "threadName" => FieldValue::Str(
                std::thread::current()
                    .name()
                    .unwrap_or("MainThread")
                    .to_owned(),
            ),
            "created" => FieldValue::Float(micros as f64 / 1e6),
            "msecs" => FieldValue::Float((micros.rem_euclid(1_000_000) / 1000) as f64),
            "relativeCreated" => FieldValue::Float(
                (micros - crate::daemon::startup_time() * 1_000_000) as f64 / 1000.0,
            ),
            "module" => FieldValue::Str(r.name.rsplit('.').next().unwrap_or(r.name).to_owned()),
            "filename" => FieldValue::Str(format!(
                "{}.py",
                r.name.rsplit('.').next().unwrap_or(r.name)
            )),
            "pathname" => FieldValue::Str(format!("{}.py", r.name.replace('.', "/"))),
            "funcName" => FieldValue::Str(String::new()),
            "lineno" => FieldValue::Int(0),
            _ => return None,
        })
    }

    /// `Formatter.format(record)`.
    pub(crate) fn format(&self, r: &Record<'_>) -> String {
        let mut out = String::new();
        let mut rest = self.format.as_str();
        while let Some(at) = rest.find('%') {
            out.push_str(&rest[..at]);
            rest = &rest[at + 1..];
            if let Some(after) = rest.strip_prefix('%') {
                out.push('%');
                rest = after;
                continue;
            }
            let Some(after) = rest.strip_prefix('(') else {
                out.push('%');
                continue;
            };
            let Some(close) = after.find(')') else {
                out.push('%');
                continue;
            };
            let key = &after[..close];
            let mut spec = &after[close + 1..];
            let flags_end = spec
                .find(|c: char| !"-+ #0".contains(c))
                .unwrap_or(spec.len());
            let flags = &spec[..flags_end];
            spec = &spec[flags_end..];
            let width_end = spec
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(spec.len());
            let width: usize = spec[..width_end].parse().unwrap_or(0);
            spec = &spec[width_end..];
            let mut precision = None;
            if let Some(p) = spec.strip_prefix('.') {
                let end = p.find(|c: char| !c.is_ascii_digit()).unwrap_or(p.len());
                precision = p[..end].parse::<usize>().ok();
                spec = &p[end..];
            }
            let Some(conv) = spec.chars().next() else {
                break;
            };
            rest = &spec[conv.len_utf8()..];
            let value = self.field(key, r).unwrap_or(FieldValue::Str(String::new()));
            let text = value.convert(conv, precision);
            let zero = flags.contains('0') && !flags.contains('-') && conv != 's';
            if text.chars().count() >= width {
                out.push_str(&text);
            } else if flags.contains('-') {
                let _ = write!(out, "{text:<width$}");
            } else if zero {
                let (sign, digits) = text
                    .strip_prefix('-')
                    .map_or(("", text.as_str()), |d| ("-", d));
                let _ = write!(out, "{sign}{digits:0>w$}", w = width - sign.len());
            } else {
                let _ = write!(out, "{text:>width$}");
            }
        }
        out.push_str(rest);
        out
    }
}

enum FieldValue {
    Str(String),
    Int(i64),
    Float(f64),
}

impl FieldValue {
    fn convert(&self, conv: char, precision: Option<usize>) -> String {
        match (self, conv) {
            (FieldValue::Str(s), 'r') => config::str_repr(s),
            (FieldValue::Str(s), _) => match precision {
                Some(p) => s.chars().take(p).collect(),
                None => s.clone(),
            },
            (FieldValue::Int(i), 'f') => format!("{:.*}", precision.unwrap_or(6), *i as f64),
            (FieldValue::Int(i), _) => i.to_string(),
            (FieldValue::Float(f), 'd' | 'i') => (f.trunc() as i64).to_string(),
            (FieldValue::Float(f), 'f') => format!("{:.*}", precision.unwrap_or(6), f),
            (FieldValue::Float(f), _) => {
                // Python's str(float).
                if f.fract() == 0.0 && f.abs() < 1e16 {
                    format!("{f:.1}")
                } else {
                    f.to_string()
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------

/// An open file, and the device and inode it had when opened.
struct OpenFile {
    file: std::fs::File,
    dev: u64,
    ino: u64,
}

fn open_log_file(path: &PathBuf, truncate: bool) -> std::io::Result<OpenFile> {
    use std::os::unix::fs::MetadataExt;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(!truncate)
        .write(true)
        .truncate(truncate)
        .open(path)?;
    let m = file.metadata()?;
    Ok(OpenFile {
        file,
        dev: m.dev(),
        ino: m.ino(),
    })
}

enum Sink {
    Stderr,
    Stdout,
    File {
        path: PathBuf,
        watched: bool,
        open: Mutex<Option<OpenFile>>,
    },
    Syslog {
        facility: i64,
        target: SyslogTarget,
    },
    Null,
}

enum SyslogTarget {
    Unix {
        path: PathBuf,
        sock: Mutex<Option<std::os::unix::net::UnixDatagram>>,
    },
    Udp {
        addr: String,
        sock: Mutex<Option<std::net::UdpSocket>>,
    },
}

fn unix_syslog(path: &PathBuf) -> std::io::Result<std::os::unix::net::UnixDatagram> {
    let s = std::os::unix::net::UnixDatagram::unbound()?;
    s.connect(path)?;
    Ok(s)
}

/// `SysLogHandler.mapPriority`.
fn syslog_severity(levelno: u8) -> i64 {
    match levelno {
        50.. => 2,
        40..=49 => 3,
        30..=39 => 4,
        20..=29 => 6,
        _ => 7,
    }
}

struct Handler {
    sink: Sink,
    level: u8,
    formatter: Formatter,
}

impl Handler {
    /// Open the handler as Python's constructor does, which is where a
    /// missing directory or syslog socket stops v4 from starting.
    fn open(c: &HandlerConfig) -> std::io::Result<Handler> {
        let sink = match &c.kind {
            HandlerKind::Stderr => Sink::Stderr,
            HandlerKind::Stdout => Sink::Stdout,
            HandlerKind::Null => Sink::Null,
            HandlerKind::File {
                path,
                truncate,
                watched,
            } => {
                let path = PathBuf::from(path);
                let f = open_log_file(&path, *truncate)?;
                Sink::File {
                    path,
                    watched: *watched,
                    open: Mutex::new(Some(f)),
                }
            }
            HandlerKind::SyslogUnix { path, facility } => {
                let path = PathBuf::from(path);
                let sock = unix_syslog(&path)?;
                Sink::Syslog {
                    facility: *facility,
                    target: SyslogTarget::Unix {
                        path,
                        sock: Mutex::new(Some(sock)),
                    },
                }
            }
            HandlerKind::SyslogUdp {
                host,
                port,
                facility,
            } => Sink::Syslog {
                facility: *facility,
                target: SyslogTarget::Udp {
                    addr: format!("{host}:{port}"),
                    sock: Mutex::new(None),
                },
            },
        };
        Ok(Handler {
            sink,
            level: c.level,
            formatter: Formatter::new(&c.format, c.datefmt.as_deref()),
        })
    }

    /// Write one formatted record. `levelno` picks the syslog severity and
    /// `raw` (the record's message) goes into the error report.
    fn write(&self, msg: &str, levelno: u8, raw: &str) {
        let result = match &self.sink {
            Sink::Null => Ok(()),
            Sink::Stderr => writeln!(std::io::stderr().lock(), "{msg}"),
            Sink::Stdout => {
                let mut out = std::io::stdout().lock();
                writeln!(out, "{msg}").and_then(|_| out.flush())
            }
            Sink::File {
                path,
                watched,
                open,
            } => {
                let mut guard = open.lock().unwrap_or_else(|e| e.into_inner());
                if *watched {
                    // WatchedFileHandler.reopenIfNeeded()
                    use std::os::unix::fs::MetadataExt;
                    let same = std::fs::metadata(path).ok().is_some_and(|m| {
                        guard
                            .as_ref()
                            .is_some_and(|o| o.dev == m.dev() && o.ino == m.ino())
                    });
                    if !same {
                        *guard = open_log_file(path, false).ok();
                    }
                }
                match guard.as_mut() {
                    Some(o) => writeln!(o.file, "{msg}"),
                    None => Err(std::io::Error::other("log file not open")),
                }
            }
            Sink::Syslog { facility, target } => {
                let packet = format!("<{}>{msg}\0", (facility << 3) | syslog_severity(levelno));
                match target {
                    SyslogTarget::Unix { path, sock } => {
                        let mut s = sock.lock().unwrap_or_else(|e| e.into_inner());
                        let first = s.as_ref().map(|s| s.send(packet.as_bytes()));
                        match first {
                            Some(Ok(_)) => Ok(()),
                            _ => {
                                // Python reconnects once and retries.
                                *s = unix_syslog(path).ok();
                                match s.as_ref() {
                                    Some(s) => s.send(packet.as_bytes()).map(|_| ()),
                                    None => Err(std::io::Error::other("syslog socket")),
                                }
                            }
                        }
                    }
                    SyslogTarget::Udp { addr, sock } => {
                        let mut s = sock.lock().unwrap_or_else(|e| e.into_inner());
                        if s.is_none() {
                            *s = std::net::UdpSocket::bind("0.0.0.0:0")
                                .or_else(|_| std::net::UdpSocket::bind("[::]:0"))
                                .ok();
                        }
                        match s.as_ref() {
                            Some(s) => s.send_to(packet.as_bytes(), addr.as_str()).map(|_| ()),
                            None => Err(std::io::Error::other("syslog socket")),
                        }
                    }
                }
            }
        };
        if let Err(e) = result {
            // Handler.handleError()
            let _ = writeln!(
                std::io::stderr().lock(),
                "--- Logging error ---\n{e}\nMessage: {}",
                config::str_repr(raw)
            );
        }
    }
}

// ---------------------------------------------------------------------
// Background writer
// ---------------------------------------------------------------------

/// One write for the background writer.
enum Out {
    /// A formatted record for handler `idx` of `model`.
    Line {
        model: Arc<Model>,
        idx: usize,
        msg: String,
        levelno: u8,
        raw: String,
    },
    /// `logging.lastResort`: a bare message on stderr.
    Stderr(String),
    /// Acknowledge once everything queued before has been written.
    Flush(std::sync::mpsc::SyncSender<()>),
}

/// The daemon's background log writer, once started.
static WRITER: OnceLock<std::sync::mpsc::SyncSender<Out>> = OnceLock::new();

/// Records queued for the background writer before callers wait: at
/// about 250 bytes a record, up to some 64 MiB, which is several seconds
/// of logging at the highest query rates the load bench reaches (a busy
/// disk held writes for over 6 s there). The queue only fills while the
/// log cannot be written.
const WRITER_QUEUE: usize = 1 << 18;

/// Hand `out` to the background writer, or give it back when there is
/// none (the command line tools write directly).
fn enqueue(out: Out) -> Result<(), Out> {
    match WRITER.get() {
        Some(tx) => tx.send(out).map_err(|e| e.0),
        None => Err(out),
    }
}

/// Write log records on a thread of their own, in the order they were
/// logged. v4 logs from many processes, each writing its own records, so
/// a slow log file or a busy journal holds up one worker; irrd-ng is one
/// process, and with direct writes one write held up by the disk stopped
/// every thread that logged meanwhile, which is every query (the load
/// bench saw whole-server stalls of about a second). The records, their
/// text and their order are unchanged. Only the daemon uses this; call
/// [`flush`] before the process exits.
pub(crate) fn start_background_writer() {
    WRITER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Out>(WRITER_QUEUE);
        let spawned = std::thread::Builder::new()
            .name("log-writer".into())
            .spawn(move || {
                while let Ok(out) = rx.recv() {
                    match out {
                        Out::Line {
                            model,
                            idx,
                            msg,
                            levelno,
                            raw,
                        } => {
                            if let Some(h) = model.handlers.get(idx) {
                                h.write(&msg, levelno, &raw);
                            }
                        }
                        Out::Stderr(line) => {
                            let _ = writeln!(std::io::stderr().lock(), "{line}");
                        }
                        Out::Flush(ack) => {
                            let _ = ack.send(());
                        }
                    }
                }
            });
        if spawned.is_err() {
            // No thread: a sender whose receiver is gone, so every record
            // is written directly.
            return std::sync::mpsc::sync_channel::<Out>(0).0;
        }
        tx
    });
}

/// Calls [`flush`] when dropped.
pub(crate) struct FlushOnDrop;

impl Drop for FlushOnDrop {
    fn drop(&mut self) {
        flush();
    }
}

/// Wait until the background writer has written everything logged so far.
pub(crate) fn flush() {
    let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel(1);
    if enqueue(Out::Flush(ack_tx)).is_ok() {
        let _ = ack_rx.recv();
    }
}

// ---------------------------------------------------------------------
// Loggers
// ---------------------------------------------------------------------

struct Model {
    handlers: Vec<Handler>,
    root: LoggerConfig,
    loggers: std::collections::HashMap<String, LoggerConfig>,
}

impl Model {
    /// The lowest level any logger lets through, given the root level.
    fn min_level(&self, root: u8) -> u8 {
        self.loggers
            .values()
            .filter_map(|l| l.level)
            .filter(|l| *l > 0)
            .fold(root, u8::min)
    }

    fn effective_level(&self, name: &str, root: u8) -> u8 {
        let mut n = name;
        loop {
            if let Some(level) = self.loggers.get(n).and_then(|l| l.level).filter(|l| *l > 0) {
                return level;
            }
            match n.rfind('.') {
                Some(i) => n = &n[..i],
                None => return root,
            }
        }
    }

    /// `Logger.handle()`: the logger's handlers, then its ancestors' while
    /// propagation allows, then the root's.
    fn handle(self: &Arc<Self>, r: &Record<'_>, root: u8) {
        if r.levelno < self.effective_level(r.name, root) {
            return;
        }
        let mut found = 0;
        let mut n = Some(r.name);
        while let Some(name) = n {
            if let Some(l) = self.loggers.get(name) {
                for h in &l.handlers {
                    found += 1;
                    self.emit(*h, r);
                }
                if !l.propagate {
                    return;
                }
            }
            n = name.rfind('.').map(|i| &name[..i]);
        }
        for h in &self.root.handlers {
            found += 1;
            self.emit(*h, r);
        }
        if found == 0 && r.levelno >= 30 {
            // logging.lastResort
            let line = r.message.to_owned();
            if let Err(Out::Stderr(line)) = enqueue(Out::Stderr(line)) {
                let _ = writeln!(std::io::stderr().lock(), "{line}");
            }
        }
    }

    /// `Handler.handle()`: format the record and write it, through the
    /// background writer when there is one.
    fn emit(self: &Arc<Self>, idx: usize, r: &Record<'_>) {
        let Some(h) = self.handlers.get(idx) else {
            return;
        };
        if r.levelno < h.level || matches!(h.sink, Sink::Null) {
            return;
        }
        let msg = h.formatter.format(r);
        let out = Out::Line {
            model: self.clone(),
            idx,
            msg,
            levelno: r.levelno,
            raw: if WRITER.get().is_some() {
                r.message.to_owned()
            } else {
                String::new()
            },
        };
        if let Err(Out::Line { msg, .. }) = enqueue(out) {
            h.write(&msg, r.levelno, r.message);
        }
    }
}

/// v4's `LOGGING`: the console handler, or the log file in its place.
fn v4_default(logfile: Option<&str>) -> LogConfig {
    let kind = match logfile {
        Some(path) => HandlerKind::File {
            path: path.to_owned(),
            truncate: false,
            watched: true,
        },
        None => HandlerKind::Stderr,
    };
    LogConfig {
        handlers: vec![HandlerConfig {
            kind,
            level: 0,
            format: VERBOSE.to_owned(),
            datefmt: None,
        }],
        root: LoggerConfig {
            level: None,
            handlers: vec![0],
            propagate: true,
        },
        // Library loggers v4 tunes down do not exist in irrd-ng.
        loggers: Vec::new(),
        notices: Vec::new(),
    }
}

static MODEL: RwLock<Option<Arc<Model>>> = RwLock::new(None);
static ROOT_LEVEL: AtomicU8 = AtomicU8::new(20);
static MIN_LEVEL: AtomicU8 = AtomicU8::new(20);
static INSTALLED: OnceLock<()> = OnceLock::new();

fn tracing_levelno(level: &Level, critical: bool) -> u8 {
    match *level {
        Level::ERROR if critical => 50,
        Level::ERROR => 40,
        Level::WARN => 30,
        Level::INFO => 20,
        Level::DEBUG | Level::TRACE => 10,
    }
}

#[derive(Default)]
struct Fields {
    message: String,
    critical: bool,
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        if field.name() == "critical" {
            self.critical = value;
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        }
    }
}

struct PyLayer;

/// irrd's loggers, and the root logger v4 logs some daemon messages to.
fn is_irrd(meta: &Metadata<'_>) -> bool {
    meta.target().starts_with("irrd") || meta.target() == ROOT_LOGGER
}

/// The root logger's name, as v4's `logging.info(...)` calls show it.
pub(crate) const ROOT_LOGGER: &str = "root";

impl<S: Subscriber> Layer<S> for PyLayer {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, meta: &Metadata<'_>, _: Context<'_, S>) -> bool {
        is_irrd(meta) && tracing_levelno(meta.level(), true) >= MIN_LEVEL.load(Ordering::Relaxed)
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        use tracing::level_filters::LevelFilter;
        Some(match MIN_LEVEL.load(Ordering::Relaxed) {
            0..=10 => LevelFilter::DEBUG,
            11..=20 => LevelFilter::INFO,
            21..=30 => LevelFilter::WARN,
            _ => LevelFilter::ERROR,
        })
    }

    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let meta = event.metadata();
        if !is_irrd(meta) {
            return;
        }
        let mut f = Fields::default();
        event.record(&mut f);
        let model = MODEL.read().ok().and_then(|m| m.clone());
        if let Some(model) = model {
            let r = Record {
                name: meta.target(),
                levelno: tracing_levelno(meta.level(), f.critical),
                message: &f.message,
                time: store::Timestamp::now(),
            };
            model.handle(&r, ROOT_LEVEL.load(Ordering::Relaxed));
        }
    }
}

fn swap(model: Model, root: u8) {
    MIN_LEVEL.store(model.min_level(root), Ordering::Relaxed);
    ROOT_LEVEL.store(root, Ordering::Relaxed);
    if let Ok(mut m) = MODEL.write() {
        *m = Some(Arc::new(model));
    }
    tracing::callsite::rebuild_interest_cache();
}

/// Install the logging layer with v4's module-level configuration: stderr,
/// root at INFO. Safe to call more than once.
pub(crate) fn install() {
    INSTALLED.get_or_init(|| {
        if let Ok(model) = build(&v4_default(None)) {
            swap(model, 20);
        }
        let _ = tracing_subscriber::registry().with(PyLayer).try_init();
    });
}

fn build(c: &LogConfig) -> std::io::Result<Model> {
    let handlers = c
        .handlers
        .iter()
        .map(Handler::open)
        .collect::<std::io::Result<Vec<_>>>()?;
    Ok(Model {
        handlers,
        root: c.root.clone(),
        loggers: c.loggers.iter().cloned().collect(),
    })
}

fn setting(cfg: &config::Configuration, k: &str) -> Option<String> {
    cfg.get_setting_live(k)
        .ok()
        .flatten()
        .and_then(|v| v.as_str().map(str::to_owned))
}

/// The root level `_commit_staging()` sets: `log.level`, default INFO.
fn root_level(cfg: &config::Configuration) -> u8 {
    setting(cfg, "log.level")
        .and_then(|l| pylogconf::check_level(&pylogconf::Py::Str(l)).ok())
        .unwrap_or(20)
}

/// Why the logging configuration could not be applied: the last line of
/// the traceback v4 would print.
#[derive(Debug)]
pub(crate) struct ApplyError(pub(crate) String);

/// `Configuration(path, commit=True)`'s logging: v4's default, the log
/// file, or the operator's `dictConfig`, then the root level. Returns the
/// parts of a `logging_config_path` file irrd-ng left out.
pub(crate) fn apply(cfg: &config::Configuration) -> Result<Vec<String>, ApplyError> {
    install();
    let config = if let Some(path) = setting(cfg, "log.logging_config_path") {
        let src =
            std::fs::read(&path).map_err(|e| ApplyError(crate::messages::os_error(&e, &path)))?;
        let src = String::from_utf8_lossy(&src);
        match pylogconf::read_logging_dict(&src) {
            Ok(d) => {
                pylogconf::interpret(&d).map_err(|e| ApplyError(format!("ValueError: {e}")))?
            }
            Err(why) => {
                let mut c = v4_default(None);
                c.notices
                    .push(crate::messages::logging_config_unreadable(&path, &why));
                c
            }
        }
    } else {
        v4_default(setting(cfg, "log.logfile_path").as_deref())
    };
    let model = build(&config)
        .map_err(|e| ApplyError(format!("ValueError: Unable to configure handler: {e}")))?;
    swap(model, root_level(cfg));
    for n in &config.notices {
        tracing::warn!(target: LOG_TARGET, "{}", crate::messages::logging_config_notice(n));
    }
    Ok(config.notices)
}

/// `_commit_staging()` on SIGHUP: only the root level changes.
pub(crate) fn reload_level(cfg: &config::Configuration) {
    let model = MODEL.read().ok().and_then(|m| m.clone());
    let root = root_level(cfg);
    if let Some(m) = model {
        MIN_LEVEL.store(m.min_level(root), Ordering::Relaxed);
    }
    ROOT_LEVEL.store(root, Ordering::Relaxed);
    tracing::callsite::rebuild_interest_cache();
}

/// Install the logger from the loaded configuration (the command line
/// tools' `config_init`).
pub(crate) fn init(cfg: &config::Configuration) {
    if let Err(e) = apply(cfg) {
        eprintln!("{}", e.0);
    }
}

/// Install the logger at INFO on stderr, for tools that run without an
/// irrd.yaml (`irrd-ng import`).
pub(crate) fn init_stderr() {
    install();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(levelno: u8) -> Record<'static> {
        Record {
            name: "irrd.mirroring.scheduler",
            levelno,
            message: "Started",
            time: store::Timestamp(1_793_408_028_927_123),
        }
    }

    #[test]
    fn python_asctime() {
        assert_eq!(
            asctime(store::Timestamp(1_793_408_028_927_123)),
            "2026-10-31 00:53:48,927"
        );
    }

    #[test]
    fn formats_like_python_logging() {
        let f = Formatter::new(VERBOSE, None);
        assert_eq!(
            f.format(&record(20)),
            format!(
                "2026-10-31 00:53:48,927 irrd[{}]: [irrd.mirroring.scheduler#INFO] Started",
                std::process::id()
            )
        );
        let f = Formatter::new(
            "%(levelname)-8s|%(levelno)03d|%(msecs)03d|%(module)s %%(x)s %(message).3s",
            None,
        );
        assert_eq!(
            f.format(&record(50)),
            "CRITICAL|050|927|scheduler %(x)s Sta"
        );
        let f = Formatter::new(
            "%(asctime)s %(levelname)8s",
            Some("%Y-%m-%dT%H:%M:%S%z %a %b %j"),
        );
        assert_eq!(
            f.format(&record(30)),
            "2026-10-31T00:53:48+0000 Sat Oct 304  WARNING"
        );
    }

    #[test]
    fn logger_hierarchy_levels_and_propagation() {
        let dir = std::env::temp_dir().join(format!("irrd-ng-logging-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let (main, mirror) = (dir.join("main.log"), dir.join("mirror.log"));
        let _ = std::fs::remove_file(&main);
        let _ = std::fs::remove_file(&mirror);
        let file = |p: &PathBuf| HandlerConfig {
            kind: HandlerKind::File {
                path: p.to_string_lossy().into_owned(),
                truncate: false,
                watched: true,
            },
            level: 0,
            format: "%(name)s#%(levelname)s %(message)s".into(),
            datefmt: None,
        };
        let c = LogConfig {
            handlers: vec![file(&main), file(&mirror)],
            root: LoggerConfig {
                level: Some(10),
                handlers: vec![0],
                propagate: true,
            },
            loggers: vec![(
                "irrd.mirroring".into(),
                LoggerConfig {
                    level: Some(10),
                    handlers: vec![1],
                    propagate: false,
                },
            )],
            notices: Vec::new(),
        };
        let m = Arc::new(build(&c).expect("build"));
        // The root level is v4's log.level, INFO here; irrd.mirroring
        // keeps its own DEBUG.
        assert_eq!(m.min_level(20), 10);
        let rec = |name: &'static str, levelno| Record {
            name,
            levelno,
            message: "m",
            time: store::Timestamp(0),
        };
        m.handle(&rec("irrd.mirroring.parsers", 10), 20);
        m.handle(&rec("irrd.server.whois", 10), 20);
        m.handle(&rec("irrd.server.whois", 20), 20);
        // Log rotation: the file is moved away, the next line goes to a
        // new file at the configured path.
        std::fs::rename(&main, dir.join("main.log.1")).expect("rotate");
        m.handle(&rec("irrd.daemon.main", 40), 20);
        assert_eq!(
            std::fs::read_to_string(&mirror).expect("mirror"),
            "irrd.mirroring.parsers#DEBUG m\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("main.log.1")).expect("rotated"),
            "irrd.server.whois#INFO m\n"
        );
        assert_eq!(
            std::fs::read_to_string(&main).expect("main"),
            "irrd.daemon.main#ERROR m\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn syslog_packets_are_pythons() {
        let dir = std::env::temp_dir().join(format!("irrd-ng-syslog-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("log.sock");
        let _ = std::fs::remove_file(&path);
        let server = std::os::unix::net::UnixDatagram::bind(&path).expect("bind");
        let h = Handler::open(&HandlerConfig {
            kind: HandlerKind::SyslogUnix {
                path: path.to_string_lossy().into_owned(),
                facility: 16,
            },
            level: 0,
            format: "irrd: %(message)s".into(),
            datefmt: None,
        })
        .expect("open");
        let r = record(30);
        h.write(&h.formatter.format(&r), r.levelno, r.message);
        let mut buf = [0u8; 256];
        let n = server.recv(&mut buf).expect("recv");
        // LOG_LOCAL0 (16) << 3 | warning (4) = 132
        assert_eq!(&buf[..n], b"<132>irrd: Started\0");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
