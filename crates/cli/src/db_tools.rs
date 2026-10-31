//! `irrd_load_database`, `irrd_update_database`,
//! `irrd_database_upgrade`, `irrd_database_downgrade` and the hidden
//! `export-jsonl`.

use std::ffi::OsString;
use std::io::Write as _;
use std::process::ExitCode;

use config::Configuration;
use nrtm::file_import::{self, ImportError, ImportSettings, ParseEnv};
use store::{Store, StoreOptions};

use crate::argparse::{Opt, Parsed, Parser};
use crate::{logging, messages, settings};

const CONFIG_OPT: Opt = Opt {
    flag: "--config",
    dest: "config_file_path",
    required: false,
    int: false,
};
const SOURCE_OPT: Opt = Opt {
    flag: "--source",
    dest: "source",
    required: true,
    int: false,
};

const LOAD: Parser = Parser {
    prog: "irrd_load_database",
    usage: "usage: irrd_load_database [-h] [--config CONFIG_FILE_PATH] [--serial SERIAL]\n                          --source SOURCE\n                          input_file\n",
    help: "usage: irrd_load_database [-h] [--config CONFIG_FILE_PATH] [--serial SERIAL]\n                          --source SOURCE\n                          input_file\n\nLoad an RPSL file into the database.\n\npositional arguments:\n  input_file            the name of a file to read\n\noptions:\n  -h, --help            show this help message and exit\n  --config CONFIG_FILE_PATH\n                        use a different IRRd config file (default:\n                        /etc/irrd.yaml)\n  --serial SERIAL       serial number (optional)\n  --source SOURCE       name of the source, e.g. NTTCOM\n",
    options: &[
        CONFIG_OPT,
        Opt {
            flag: "--serial",
            dest: "serial",
            required: false,
            int: true,
        },
        SOURCE_OPT,
    ],
    positionals: &["input_file"],
};

const UPDATE: Parser = Parser {
    prog: "irrd_update_database",
    usage: "usage: irrd_update_database [-h] [--config CONFIG_FILE_PATH] --source SOURCE\n                            input_file\n",
    help: "usage: irrd_update_database [-h] [--config CONFIG_FILE_PATH] --source SOURCE\n                            input_file\n\nUpdate a database based on a RPSL file.\n\npositional arguments:\n  input_file            the name of a file to read\n\noptions:\n  -h, --help            show this help message and exit\n  --config CONFIG_FILE_PATH\n                        use a different IRRd config file (default:\n                        /etc/irrd.yaml)\n  --source SOURCE       name of the source, e.g. NTTCOM\n",
    options: &[CONFIG_OPT, SOURCE_OPT],
    positionals: &["input_file"],
};

const UPGRADE: Parser = Parser {
    prog: "irrd_database_upgrade",
    usage: "usage: irrd_database_upgrade [-h] [--config CONFIG_FILE_PATH]\n                             [--version VERSION]\n",
    help: "usage: irrd_database_upgrade [-h] [--config CONFIG_FILE_PATH]\n                             [--version VERSION]\n\nUpgrade the IRRd SQL database to a particular version by running database\nmigrations.\n\noptions:\n  -h, --help            show this help message and exit\n  --config CONFIG_FILE_PATH\n                        use a different IRRd config file (default:\n                        /etc/irrd.yaml)\n  --version VERSION     version to upgrade to (default: head, i.e. latest)\n",
    options: &[
        CONFIG_OPT,
        Opt {
            flag: "--version",
            dest: "version",
            required: false,
            int: false,
        },
    ],
    positionals: &[],
};

const DOWNGRADE: Parser = Parser {
    prog: "irrd_database_downgrade",
    usage: "usage: irrd_database_downgrade [-h] [--config CONFIG_FILE_PATH]\n                               --version VERSION\n",
    help: "usage: irrd_database_downgrade [-h] [--config CONFIG_FILE_PATH]\n                               --version VERSION\n\nDowngrade the IRRd SQL database to a particular version by running database\nmigrations. See release notes.\n\noptions:\n  -h, --help            show this help message and exit\n  --config CONFIG_FILE_PATH\n                        use a different IRRd config file (default:\n                        /etc/irrd.yaml)\n  --version VERSION     version to downgrade to (see release notes)\n",
    options: &[
        CONFIG_OPT,
        Opt {
            flag: "--version",
            dest: "version",
            required: true,
            int: false,
        },
    ],
    positionals: &[],
};

const EXPORT: Parser = Parser {
    prog: "irrd-ng export-jsonl",
    usage: "usage: irrd-ng export-jsonl [-h] [--config CONFIG_FILE_PATH] --table TABLE\n                            [--output-dir OUTPUT_DIR]\n",
    help: "usage: irrd-ng export-jsonl [-h] [--config CONFIG_FILE_PATH] --table TABLE\n                            [--output-dir OUTPUT_DIR]\n\nWrite the canonical JSONL export of a store table (or 'all' tables into\nOUTPUT_DIR as TABLE.jsonl) for the three-way load check.\n\noptions:\n  -h, --help            show this help message and exit\n  --config CONFIG_FILE_PATH\n                        use a different IRRd config file (default:\n                        /etc/irrd.yaml)\n  --table TABLE         a v4 table name, or 'all'\n  --output-dir OUTPUT_DIR\n                        directory for 'all' (default: standard output for\n                        one table)\n",
    options: &[
        CONFIG_OPT,
        Opt {
            flag: "--table",
            dest: "table",
            required: true,
            int: false,
        },
        Opt {
            flag: "--output-dir",
            dest: "output_dir",
            required: false,
            int: false,
        },
    ],
    positionals: &[],
};

type Args = std::collections::HashMap<&'static str, String>;

fn parse(p: &Parser, args: &[OsString]) -> Result<Args, ExitCode> {
    match p.parse(args.get(1..).unwrap_or_default()) {
        Parsed::Args(a) => Ok(a),
        Parsed::Help => Err(ExitCode::SUCCESS),
        Parsed::Error => Err(ExitCode::from(2)),
    }
}

/// `config_init(args.config_file_path)`, then the logger.
fn load_config(args: &Args) -> Result<Configuration, ExitCode> {
    match Configuration::load(args.get("config_file_path").map(String::as_str)) {
        Ok(c) => {
            logging::init(&c);
            Ok(c)
        }
        Err(e) => {
            eprintln!("{}", messages::configuration_error(&e.to_string()));
            Err(ExitCode::from(1))
        }
    }
}

fn open_store(cfg: &Configuration, bulk_load: bool) -> Result<Store, ExitCode> {
    let mut options = StoreOptions::new(settings::store_path());
    options.bulk_load = bulk_load;
    Store::open(&options, settings::store_settings(cfg)).map_err(|e| {
        eprintln!("{e}");
        ExitCode::from(1)
    })
}

/// v4 refuses to run the loaders on a standby.
fn check_standby(cfg: &Configuration) -> Result<(), ExitCode> {
    if settings::truthy(cfg, "readonly_standby") {
        println!("{}", messages::READONLY_STANDBY);
        // sys.exit(-1)
        return Err(ExitCode::from(255));
    }
    Ok(())
}

fn check_import_sources(cfg: &Configuration, source: &str) -> Result<(), ExitCode> {
    if settings::truthy(cfg, &format!("sources.{source}.import_source"))
        || settings::truthy(cfg, &format!("sources.{source}.import_serial_source"))
    {
        println!("{}", messages::import_source_set(source));
        return Err(ExitCode::from(2));
    }
    Ok(())
}

fn read_paragraphs(path: &str) -> Result<Vec<String>, ExitCode> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let text = rpsl::decode_rpsl_file(&bytes);
            drop(bytes);
            Ok(rpsl::split_paragraphs_rpsl(&text, true))
        }
        Err(e) => {
            eprintln!("{}", messages::os_error(&e, path));
            Err(ExitCode::from(1))
        }
    }
}

struct Prepared {
    cfg: Configuration,
    store: Store,
    source: String,
    file: String,
}

fn prepare(p: &Parser, args: &[OsString], bulk_load: bool) -> Result<(Prepared, Args), ExitCode> {
    let a = parse(p, args)?;
    let cfg = load_config(&a)?;
    check_standby(&cfg)?;
    let source = a.get("source").cloned().unwrap_or_default();
    check_import_sources(&cfg, &source)?;
    let store = open_store(&cfg, bulk_load)?;
    let file = a.get("input_file").cloned().unwrap_or_default();
    Ok((
        Prepared {
            cfg,
            store,
            source,
            file,
        },
        a,
    ))
}

fn parse_file(p: &Prepared, keep_plain_text: bool) -> Result<file_import::ParsedFile, ExitCode> {
    let rpsl_settings = p.cfg.rpsl_settings().map_err(|e| {
        eprintln!("{e}");
        ExitCode::from(1)
    })?;
    let keyring = rpsl::Keyring::new();
    let roa = {
        let r = p.store.read().map_err(store_err)?;
        rpki::BulkRouteRoaValidator::from_store(&r.view(), settings::rpki_excluded_sources(&p.cfg))
            .map_err(store_err)?
    };
    let scopefilter = rpki::ScopeFilterValidator::new(settings::scopefilter_config(&p.cfg));
    let paragraphs = read_paragraphs(&p.file)?;
    let import = import_settings(p, keep_plain_text);
    let env = ParseEnv {
        rpsl: &rpsl_settings,
        keyring: &keyring,
        roa_validator: Some(&roa),
        scopefilter: &scopefilter,
    };
    let result = file_import::parse_paragraphs(&paragraphs, &import, &env);
    drop(paragraphs);
    result.map_err(import_failed)
}

fn store_err(e: store::StoreError) -> ExitCode {
    eprintln!("{e}");
    ExitCode::from(1)
}

/// `irrd_load_database`: parse and write in one transaction, a chunk of
/// the file at a time, as v4 streams through the file.
pub(crate) fn load_database(args: &[OsString]) -> ExitCode {
    let (p, a) = match prepare(&LOAD, args, true) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let serial = a.get("serial").and_then(|s| crate::argparse::py_int(s));
    tracing::debug!(
        target: file_import::LOG_TARGET,
        "{}",
        nrtm::messages::starting_file_import(&p.source, &p.file)
    );
    let rpsl_settings = match p.cfg.rpsl_settings() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let paragraphs = match read_paragraphs(&p.file) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let reserve = paragraphs.iter().map(String::len).sum::<usize>() * 5;
    let job = std::sync::Arc::new(LoadJob {
        paragraphs,
        import: import_settings(&p, false),
        rpsl_settings,
        keyring: rpsl::Keyring::new(),
        scopefilter: rpki::ScopeFilterValidator::new(settings::scopefilter_config(&p.cfg)),
        rpki_excluded: settings::rpki_excluded_sources(&p.cfg),
    });
    // A full reload of one source: commits need not sync, as v4's single
    // transaction either lands whole or not at all. The marker makes an
    // interrupted load refuse to open instead of serving a partial store.
    if let Err(e) = p.store.begin_bulk_load(&p.source) {
        return store_err(e);
    }
    let failure: std::sync::Arc<std::sync::Mutex<Option<ImportError>>> = Default::default();
    let fail_slot = failure.clone();
    let result = p.store.write_reserving(reserve, move |tx| {
        let source = &job.import.source;
        let roa = rpki::BulkRouteRoaValidator::from_store(
            &tx.read_unflushed(),
            job.rpki_excluded.clone(),
        )?;
        tx.delete_all_rpsl_objects_with_journal(source, false)?;
        tx.disable_journaling();
        let env = ParseEnv {
            rpsl: &job.rpsl_settings,
            keyring: &job.keyring,
            roa_validator: Some(&roa),
            scopefilter: &job.scopefilter,
        };
        match file_import::run_file_import(tx, &job.paragraphs, &job.import, &env, serial) {
            Ok(c) => Ok(c),
            Err(file_import::StreamError::Store(e)) => Err(e),
            Err(file_import::StreamError::Import(e)) => {
                if let Ok(mut f) = fail_slot.lock() {
                    *f = Some(e);
                }
                Err(store::StoreError::Aborted(String::new()))
            }
        }
    });
    // The transaction committed or rolled back as a whole: either way the
    // store is complete again once synced.
    if let Err(e) = p.store.finish_bulk_load() {
        return store_err(e);
    }
    if let Some(e) = failure.lock().ok().and_then(|mut f| f.take()) {
        return import_failed(e);
    }
    match result {
        Ok((counters, _)) => {
            file_import::log_file_import_report(&p.source, &counters);
            ExitCode::SUCCESS
        }
        Err(e) => store_err(e),
    }
}

struct LoadJob {
    paragraphs: Vec<String>,
    import: ImportSettings,
    rpsl_settings: rpsl::RpslSettings,
    keyring: rpsl::Keyring,
    scopefilter: rpki::ScopeFilterValidator,
    rpki_excluded: std::collections::HashSet<String>,
}

fn import_settings(p: &Prepared, keep_plain_text: bool) -> ImportSettings {
    ImportSettings {
        source: p.source.clone(),
        object_class_filter: settings::object_class_filter(&p.cfg, &p.source),
        strict_import_keycert_objects: settings::truthy(
            &p.cfg,
            &format!("sources.{}.strict_import_keycert_objects", p.source),
        ),
        direct_error_return: true,
        keep_plain_text,
    }
}

fn import_failed(e: ImportError) -> ExitCode {
    match e {
        ImportError::Rpsl(msg) => {
            println!("{}", messages::error_processing_object(&msg));
        }
        ImportError::Uncaught(msg) => {
            eprintln!("{msg}");
        }
    }
    ExitCode::from(1)
}

/// `irrd_update_database`
pub(crate) fn update_database(args: &[OsString]) -> ExitCode {
    let (p, _) = match prepare(&UPDATE, args, false) {
        Ok(v) => v,
        Err(c) => return c,
    };
    tracing::debug!(
        target: file_import::LOG_TARGET,
        "{}",
        nrtm::messages::starting_update_import(&p.source, &p.file)
    );
    let parsed = match parse_file(&p, true) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let source = p.source.clone();
    let actions = std::sync::Arc::new(parsed.actions);
    let result = p
        .store
        .write(move |tx| file_import::apply_update_import(tx, &source, &actions));
    match result {
        Ok(counts) => {
            file_import::log_update_report(&p.source, &p.file, &parsed.counters, &counts);
            ExitCode::SUCCESS
        }
        Err(e) => store_err(e),
    }
}

/// v4's alembic revisions, oldest first.
const REVISIONS: &[&str] = &[
    "28dc1cd85bdc",
    "e07863eac52f",
    "64a3d6faf6d4",
    "a8609af97aa3",
    "181670a62643",
    "1743f98a456d",
    "39e4f15ed80c",
    "4a514ead8fc2",
    "a7766c144d61",
    "f4c837d8258c",
    "b175c262448f",
    "893d0d5363b3",
    "8744b4b906bb",
    "0548f1aa4f10",
    "8b8357acd333",
    "fd4473bc1a10",
    "5bbbc2989aa6",
    "500027f85a55",
    "5d942647566e",
    "50d1a0ef58cb",
    "2353e60e63f8",
    "44ceb7efbcde",
    "b7b3c367f9ba",
    "a635d2217a48",
    "e1e649b5f8bb",
];

/// Resolve an alembic target as v4 would, with the database at head.
/// `Err` is alembic's `CommandError` text.
fn resolve_revision(version: &str, upgrade: bool) -> Result<(), String> {
    if matches!(version, "head" | "heads" | "base") {
        return Ok(());
    }
    if let Some(n) = version.strip_prefix('+').and_then(crate::argparse::py_int) {
        if upgrade && n > 0 {
            return Err(messages::relative_revision(version, n));
        }
        return Ok(());
    }
    if let Some(n) = version.strip_prefix('-').and_then(crate::argparse::py_int) {
        if upgrade || n as usize > REVISIONS.len() {
            return Err(messages::relative_revision(version, n));
        }
        return Ok(());
    }
    let matches = if version.len() >= 4 {
        REVISIONS.iter().filter(|r| r.starts_with(version)).count()
    } else {
        REVISIONS.iter().filter(|r| **r == version).count()
    };
    if matches == 1 {
        Ok(())
    } else {
        Err(messages::cant_locate_revision(version))
    }
}

fn schema_tool(p: &Parser, args: &[OsString], upgrade: bool) -> ExitCode {
    let a = match parse(p, args) {
        Ok(a) => a,
        Err(c) => return c,
    };
    let cfg = match load_config(&a) {
        Ok(c) => c,
        Err(c) => return c,
    };
    let version = a.get("version").cloned().unwrap_or_else(|| "head".into());
    // Opening the store read-write creates it or migrates it to the
    // current schema: the embedded store is always at head.
    if let Err(c) = open_store(&cfg, false) {
        return c;
    }
    if let Err(e) = resolve_revision(&version, upgrade) {
        eprintln!("{e}");
        return ExitCode::from(1);
    }
    if upgrade {
        println!("{}", messages::UPGRADE_SUCCESSFUL);
    } else {
        println!("{}", messages::DOWNGRADE_SUCCESSFUL);
    }
    ExitCode::SUCCESS
}

/// `irrd_database_upgrade`
pub(crate) fn database_upgrade(args: &[OsString]) -> ExitCode {
    schema_tool(&UPGRADE, args, true)
}

/// `irrd_database_downgrade`
pub(crate) fn database_downgrade(args: &[OsString]) -> ExitCode {
    schema_tool(&DOWNGRADE, args, false)
}

/// `irrd-ng export-jsonl`
pub(crate) fn export_jsonl(args: &[OsString]) -> ExitCode {
    let a = match parse(&EXPORT, args) {
        Ok(a) => a,
        Err(c) => return c,
    };
    let cfg = match load_config(&a) {
        Ok(c) => c,
        Err(c) => return c,
    };
    let _ = cfg;
    let mut options = StoreOptions::new(settings::store_path());
    options.read_only = true;
    let st = match Store::open(&options, store::StoreSettings::default()) {
        Ok(s) => s,
        Err(e) => return store_err(e),
    };
    let r = match st.read() {
        Ok(r) => r,
        Err(e) => return store_err(e),
    };
    let view = r.view();
    let table = a.get("table").cloned().unwrap_or_default();
    let tables: Vec<&str> = if table == "all" {
        store::export::EXPORT_TABLES.to_vec()
    } else if store::export::EXPORT_TABLES.contains(&table.as_str()) {
        vec![table.as_str()]
    } else {
        eprintln!("{}", messages::unknown_export_table(&table));
        return ExitCode::from(2);
    };
    let out_dir = a.get("output_dir");
    if table == "all" && out_dir.is_none() {
        eprintln!("{}", messages::EXPORT_ALL_NEEDS_DIR);
        return ExitCode::from(2);
    }
    for t in tables {
        let res = match out_dir {
            Some(d) => {
                let path = std::path::Path::new(d).join(format!("{t}.jsonl"));
                match std::fs::File::create(&path) {
                    Ok(f) => {
                        let mut w = std::io::BufWriter::new(f);
                        store::export::export_table(&view, t, &mut w).and_then(|_| {
                            w.flush()
                                .map_err(|e| store::StoreError::Io(path.clone(), e))
                        })
                    }
                    Err(e) => Err(store::StoreError::Io(path, e)),
                }
            }
            None => {
                let stdout = std::io::stdout();
                let mut w = std::io::BufWriter::new(stdout.lock());
                store::export::export_table(&view, t, &mut w).and_then(|_| {
                    w.flush()
                        .map_err(|e| store::StoreError::Io("<stdout>".into(), e))
                })
            }
        };
        if let Err(e) = res {
            return store_err(e);
        }
    }
    ExitCode::SUCCESS
}

/// `irrd-ng store-info`: schema version, map size and per-table sizes.
pub(crate) fn store_info(_args: &[OsString]) -> ExitCode {
    let mut options = StoreOptions::new(settings::store_path());
    options.read_only = true;
    let st = match Store::open(&options, store::StoreSettings::default()) {
        Ok(s) => s,
        Err(e) => return store_err(e),
    };
    match (st.info(), st.table_stats()) {
        (Ok(info), Ok(stats)) => {
            println!(
                "path {}\nschema_version {}\nmap_size {}\nused_bytes {}",
                info.path.display(),
                info.schema_version,
                info.map_size,
                info.used_bytes
            );
            for (name, entries, bytes) in stats {
                println!("{name:<28} {entries:>12} entries {bytes:>14} bytes");
            }
            ExitCode::SUCCESS
        }
        (Err(e), _) | (_, Err(e)) => store_err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alembic_targets() {
        assert!(resolve_revision("head", true).is_ok());
        assert!(resolve_revision("e1e649b5f8bb", true).is_ok());
        assert!(resolve_revision("a635", true).is_ok());
        assert!(resolve_revision("a635d2217a48", false).is_ok());
        assert_eq!(
            resolve_revision("foo", true),
            Err("alembic.util.exc.CommandError: Can't locate revision identified by 'foo'".into())
        );
        assert_eq!(
            resolve_revision("+1", true),
            Err(
                "alembic.util.exc.CommandError: Relative revision +1 didn't produce 1 migrations"
                    .into()
            )
        );
        assert!(resolve_revision("-1", false).is_ok());
    }
}
