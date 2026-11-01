//! Tools for serving data: `irrd_expire_journal`
//! (`irrd/scripts/expire_journal.py`) and the NRTMv4 server key commands
//! of `irrdctl` (`irrd/scripts/irrd_control.py`).

use std::ffi::OsString;
use std::io::{BufRead as _, Write as _};
use std::process::ExitCode;

use config::Configuration;
use nrtm::serve::keys;
use store::Timestamp;

use crate::argparse::{Opt, Parsed, Parser};
use crate::mirror_tools::{click_exception, open_store};
use crate::{logging, messages, settings};

const EXPIRE: Parser = Parser {
    prog: "irrd_expire_journal",
    usage: "usage: irrd_expire_journal [-h] [--config CONFIG_FILE_PATH]\n                           [--delete-this-history-irrevocably-without-confirmation]\n                           --expire-before EXPIRE_BEFORE --source SOURCE\n",
    help: "usage: irrd_expire_journal [-h] [--config CONFIG_FILE_PATH]\n                           [--delete-this-history-irrevocably-without-confirmation]\n                           --expire-before EXPIRE_BEFORE --source SOURCE\n\nRemove journal entries from IRRd. NOTE: the journal is the only record IRRd\nkeeps of object history, removal is irrevocable.\n\noptions:\n  -h, --help            show this help message and exit\n  --config CONFIG_FILE_PATH\n                        use a different IRRd config file (default:\n                        /etc/irrd.yaml)\n  --delete-this-history-irrevocably-without-confirmation\n                        use a different IRRd config file (default:\n                        /etc/irrd.yaml)\n  --expire-before EXPIRE_BEFORE\n                        expire all entries from before this date (YYYY-MM-DD)\n  --source SOURCE       the name of the source to reload\n",
    options: &[
        Opt {
            flag: "--config",
            dest: "config_file_path",
            required: false,
            int: false,
            store_true: false,
        },
        Opt {
            flag: "--delete-this-history-irrevocably-without-confirmation",
            dest: "skip_confirmation",
            required: false,
            int: false,
            store_true: true,
        },
        Opt {
            flag: "--expire-before",
            dest: "expire_before",
            required: true,
            int: false,
            store_true: false,
        },
        Opt {
            flag: "--source",
            dest: "source",
            required: true,
            int: false,
            store_true: false,
        },
    ],
    positionals: &[],
};

const RUN_EXPORT: Parser = Parser {
    prog: "irrd-ng run-export",
    usage: "usage: irrd-ng run-export [-h] [--config CONFIG_FILE_PATH] --source SOURCE\n",
    help: "usage: irrd-ng run-export [-h] [--config CONFIG_FILE_PATH] --source SOURCE\n\nRun the export of one source now, as the scheduler would (SourceExportRunner).\n\noptions:\n  -h, --help            show this help message and exit\n  --config CONFIG_FILE_PATH\n                        use a different IRRd config file (default:\n                        /etc/irrd.yaml)\n  --source SOURCE       the name of the source to export\n",
    options: &[
        Opt {
            flag: "--config",
            dest: "config_file_path",
            required: false,
            int: false,
            store_true: false,
        },
        Opt {
            flag: "--source",
            dest: "source",
            required: true,
            int: false,
            store_true: false,
        },
    ],
    positionals: &[],
};

/// `irrd-ng run-export`: `SourceExportRunner(source).run()` on demand, as
/// the differential harness runs v4's.
pub(crate) fn run_export(args: &[OsString]) -> ExitCode {
    let a = match RUN_EXPORT.parse(args.get(1..).unwrap_or_default()) {
        Parsed::Args(a) => a,
        Parsed::Help => return ExitCode::SUCCESS,
        Parsed::Error => return ExitCode::from(2),
    };
    let cfg = match Configuration::load(a.get("config_file_path").map(String::as_str)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", messages::configuration_error(&e.to_string()));
            return ExitCode::from(1);
        }
    };
    logging::init(&cfg);
    let store = match open_store(&cfg) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let source = a.get("source").cloned().unwrap_or_default();
    let ms = settings::mirror_settings(&cfg);
    nrtm::serve::export::run_export(&store, &ms.source(&source));
    ExitCode::SUCCESS
}

/// `NRTM4_SERVER_DELTA_EXPIRY_TIME` plus one day, in microseconds.
const MINIMUM_EXPIRY_AGE: i64 = 2 * 86_400 * 1_000_000;

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The prefix of `s` one alternative of a `_strptime` group regex matches,
/// trying alternatives in order as `re` does.
fn alt<'s>(s: &'s str, alternatives: &[&[&[u8]]]) -> Vec<(&'s str, &'s str)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    for pattern in alternatives {
        if b.len() < pattern.len() {
            continue;
        }
        if pattern.iter().zip(b).all(|(class, c)| class.contains(c)) {
            out.push(s.split_at(pattern.len()));
        }
    }
    out
}

/// `datetime.strptime(value, "%Y-%m-%d")` as a UTC midnight, `None` where
/// CPython raises `ValueError`.
pub(crate) fn strptime_ymd(value: &str) -> Option<Timestamp> {
    const D: &[u8] = b"0123456789";
    const D19: &[u8] = b"123456789";
    // %Y: \d\d\d\d
    let (y, rest) = alt(value, &[&[D, D, D, D]]).into_iter().next()?;
    let rest = rest.strip_prefix('-')?;
    // %m: 1[0-2]|0[1-9]|[1-9]
    let months: &[&[&[u8]]] = &[&[b"1", b"012"], &[b"0", D19], &[D19]];
    // %d: 3[01]|[12]\d|0[1-9]|[1-9]| [1-9]
    let days: &[&[&[u8]]] = &[
        &[b"3", b"01"],
        &[b"12", D],
        &[b"0", D19],
        &[D19],
        &[b" ", D19],
    ];
    // The regex's first match, then "unconverted data remains" if it is
    // not all of the input.
    let mut found = None;
    'outer: for (m, rest) in alt(rest, months) {
        let Some(rest) = rest.strip_prefix('-') else {
            continue;
        };
        if let Some((d, rest)) = alt(rest, days).into_iter().next() {
            found = Some((m, d, rest));
            break 'outer;
        }
    }
    let (m, d, rest) = found?;
    if !rest.is_empty() {
        return None;
    }
    let y: i64 = y.parse().ok()?;
    let m: i64 = m.parse().ok()?;
    let d: i64 = d.trim().parse().ok()?;
    if y < 1 {
        return None;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if d > dim[(m - 1) as usize] {
        return None;
    }
    Some(Timestamp(days_from_civil(y, m, d) * 86_400 * 1_000_000))
}

fn ymd(t: Timestamp) -> String {
    let (y, m, d) = civil_from_days(t.0.div_euclid(86_400 * 1_000_000));
    format!("{y:04}-{m:02}-{d:02}")
}

/// `irrd_expire_journal`
pub(crate) fn expire_journal(args: &[OsString]) -> ExitCode {
    let a = match EXPIRE.parse(args.get(1..).unwrap_or_default()) {
        Parsed::Args(a) => a,
        Parsed::Help => return ExitCode::SUCCESS,
        Parsed::Error => return ExitCode::from(2),
    };
    let cfg = match Configuration::load(a.get("config_file_path").map(String::as_str)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", messages::configuration_error(&e.to_string()));
            return ExitCode::from(1);
        }
    };
    logging::init(&cfg);
    if settings::truthy(&cfg, "readonly_standby") {
        println!("{}", messages::READONLY_STANDBY);
        return ExitCode::from(255);
    }
    let Some(expire_before) = a.get("expire_before").and_then(|v| strptime_ymd(v)) else {
        println!("{}", messages::EXPIRE_INVALID_DATE);
        return ExitCode::from(255);
    };
    let source = a.get("source").cloned().unwrap_or_default();
    let minimum_expiry = Timestamp(Timestamp::now().0 - MINIMUM_EXPIRY_AGE);
    if expire_before > minimum_expiry {
        println!("{}", messages::expire_minimum(&ymd(minimum_expiry)));
        return ExitCode::from(1);
    }
    let store = match open_store(&cfg) {
        Ok(s) => s,
        Err(c) => return c,
    };
    run_expire(
        &store,
        expire_before,
        &source,
        a.contains_key("skip_confirmation"),
    )
}

/// `expire_journal()` from the journal count on.
fn run_expire(
    store: &store::Store,
    expire_before: Timestamp,
    source: &str,
    skip_confirmation: bool,
) -> ExitCode {
    let count = {
        let txn = match store.read() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(1);
            }
        };
        let view = txn.view();
        let mut n = 0usize;
        match view.journal(Some(source), None, None) {
            Ok(it) => {
                for e in it {
                    match e {
                        Ok(e) if e.timestamp < expire_before => n += 1,
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("{e}");
                            return ExitCode::from(1);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(1);
            }
        }
        n
    };
    if count == 0 {
        println!("{}", messages::EXPIRE_NOTHING);
        return ExitCode::from(1);
    }
    if !skip_confirmation {
        println!("{}", messages::expire_confirm(count, source));
        print!("> ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(0) | Err(_) => {
                eprintln!("{}", messages::EOF_ERROR);
                return ExitCode::from(1);
            }
            Ok(_) => {}
        }
        let answer = line.strip_suffix('\n').unwrap_or(&line);
        if answer != "yes" {
            println!("{}", messages::EXPIRE_CANCELLED);
            return ExitCode::from(2);
        }
    }
    let src = source.to_owned();
    if let Err(e) =
        store.write(move |tx| tx.delete_journal_entries_before_date(expire_before, &src))
    {
        eprintln!("{e}");
        return ExitCode::from(1);
    }
    println!("{}", messages::EXPIRE_COMPLETE);
    ExitCode::SUCCESS
}

/// `irrdctl nrtm4 generate-private-key`
pub(crate) fn generate_private_key() -> ExitCode {
    let key = match keys::generate_private_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    println!(
        "{}",
        messages::ctl_generated_key(&keys::private_key_pem(&key), &keys::public_key_pem(&key))
    );
    ExitCode::SUCCESS
}

/// `irrdctl nrtm4 server-show-public-key SOURCE`
pub(crate) fn server_show_public_key(cfg: &Configuration, source: &str) -> ExitCode {
    let key_of = |name: &str| -> Result<Option<keys::PrivateKey>, String> {
        match settings::str_setting(cfg, &format!("sources.{source}.{name}")) {
            Some(v) if !v.is_empty() => keys::private_key_from_str(&v).map(Some),
            _ => Ok(None),
        }
    };
    let current = match key_of("nrtm4_server_private_key") {
        Ok(Some(k)) => k,
        Ok(None) => return click_exception(&messages::ctl_not_nrtm4_server(source)),
        Err(e) => return click_exception(&e),
    };
    println!(
        "{}",
        messages::ctl_current_public_key(source, &keys::public_key_pem(&current))
    );
    match key_of("nrtm4_server_private_key_next") {
        Ok(Some(next)) => {
            println!(
                "{}",
                messages::ctl_next_public_key(&keys::public_key_pem(&next))
            );
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(e) => click_exception(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expires_only_older_entries_of_the_source() {
        let dir = tempfile::tempdir().expect("dir");
        let st = store::Store::open(
            &store::StoreOptions::new(dir.path()),
            store::StoreSettings::default(),
        )
        .expect("store");
        let day = 86_400 * 1_000_000;
        let now = Timestamp::now().0;
        let entry = |source: &str, serial: i64, age_days: i64| store::JournalEntry {
            pk: uuid::Uuid::new_v4(),
            serial_global: serial,
            rpsl_pk: "X".into(),
            source: source.into(),
            origin: store::JournalEntryOrigin::AuthChange,
            serial_nrtm: serial,
            operation: store::DatabaseOperation::AddOrUpdate,
            object_class: "mntner".into(),
            object_text: "mntner: X\n".into(),
            timestamp: Timestamp(now - age_days * day),
        };
        let entries = vec![
            entry("TEST", 1, 10),
            entry("TEST", 2, 5),
            entry("OTHER", 3, 10),
        ];
        st.write(move |tx| {
            for e in &entries {
                tx.put_journal_entry(e)?;
            }
            Ok(())
        })
        .expect("write");
        let before = Timestamp(now - 7 * day);
        assert_eq!(run_expire(&st, before, "NONE", true), ExitCode::from(1));
        assert_eq!(run_expire(&st, before, "TEST", true), ExitCode::SUCCESS);
        let txn = st.read().expect("read");
        let left: Vec<(String, i64)> = txn
            .view()
            .journal(None, None, None)
            .expect("journal")
            .map(|e| {
                let e = e.expect("entry");
                (e.source.to_owned(), e.serial_nrtm)
            })
            .collect();
        assert_eq!(left, [("OTHER".to_owned(), 3), ("TEST".to_owned(), 2)]);
    }

    #[test]
    fn strptime_like_python() {
        let day = |s: &str| strptime_ymd(s).map(ymd);
        assert_eq!(day("2026-11-01").as_deref(), Some("2026-11-01"));
        assert_eq!(day("2026-1-5").as_deref(), Some("2026-01-05"));
        assert_eq!(day("2026-01- 5").as_deref(), Some("2026-01-05"));
        assert_eq!(day("2024-02-29").as_deref(), Some("2024-02-29"));
        for bad in [
            "2025-02-29",
            "2026-13-01",
            "2026-01-011",
            "26-01-01",
            "2026/01/01",
            "2026-01-32",
            "2026-00-10",
            "",
            "2026-01-01 ",
        ] {
            assert_eq!(day(bad), None, "{bad}");
        }
        assert_eq!(
            strptime_ymd("1970-01-02"),
            Some(Timestamp(86_400 * 1_000_000))
        );
    }
}
