//! v4's log output for the command line tools: Python's logging with
//! v4's `verbose` formatter,
//! `%(asctime)s irrd[%(process)d]: [%(name)s#%(levelname)s] %(message)s`,
//! in UTC, to stderr or `log.logfile_path`, at `log.level`.
//!
//! The logger name is the event's tracing target, so code logs under v4's
//! module names (`irrd.mirroring.parsers`). An `error!` event with a
//! `critical` field is printed as `CRITICAL`, which tracing lacks.

use std::fmt::Write as _;
use std::sync::Mutex;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

struct V4Format;

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

/// `YYYY-MM-DD HH:MM:SS,mmm` in UTC, as Python's `asctime` with
/// `converter = time.gmtime`.
pub(crate) fn asctime(now: store::Timestamp) -> String {
    let s = now.to_string();
    // 2026-10-31T01:02:03.123456+00:00
    format!("{} {},{}", &s[0..10], &s[11..19], &s[20..23])
}

impl<S, N> FormatEvent<S, N> for V4Format
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        // Only irrd's own loggers: the libraries underneath (HTTP, DNS,
        // FTP) log through tracing under their crate names, which v4 does
        // not have.
        if !event.metadata().target().starts_with("irrd") {
            return Ok(());
        }
        let mut f = Fields::default();
        event.record(&mut f);
        let level = match *event.metadata().level() {
            Level::ERROR if f.critical => "CRITICAL",
            Level::ERROR => "ERROR",
            Level::WARN => "WARNING",
            Level::INFO => "INFO",
            Level::DEBUG | Level::TRACE => "DEBUG",
        };
        writeln!(
            writer,
            "{} irrd[{}]: [{}#{}] {}",
            asctime(store::Timestamp::now()),
            std::process::id(),
            event.metadata().target(),
            level,
            f.message
        )
    }
}

struct FileWriter(Mutex<std::fs::File>);

impl std::io::Write for &FileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .flush()
    }
}

/// Python level name to a tracing level. Unknown names log at INFO.
fn level_from(name: &str) -> Level {
    match name.to_ascii_uppercase().as_str() {
        "DEBUG" => Level::DEBUG,
        "WARNING" | "WARN" => Level::WARN,
        "ERROR" | "CRITICAL" => Level::ERROR,
        _ => Level::INFO,
    }
}

/// Install the logger, from the loaded configuration.
pub(crate) fn init(cfg: &config::Configuration) {
    let setting = |k: &str| -> Option<String> {
        cfg.get_setting_live(k)
            .ok()
            .flatten()
            .and_then(|v| v.as_str().map(str::to_owned))
    };
    let level = level_from(&setting("log.level").unwrap_or_else(|| "INFO".into()));
    let builder = tracing_subscriber::fmt()
        .with_max_level(level)
        .event_format(V4Format);
    let logfile = setting("log.logfile_path").and_then(|p| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .ok()
    });
    let _ = match logfile {
        Some(f) => {
            let w: &'static FileWriter = Box::leak(Box::new(FileWriter(Mutex::new(f))));
            builder.with_writer(move || w).try_init()
        }
        None => builder.with_writer(std::io::stderr).try_init(),
    };
}

/// Install the logger at INFO on stderr, for tools that run without an
/// irrd.yaml (`irrd-ng import`).
pub(crate) fn init_stderr() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .event_format(V4Format)
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_asctime() {
        assert_eq!(
            asctime(store::Timestamp(1_793_408_028_927_123)),
            "2026-10-31 00:53:48,927"
        );
    }
}
