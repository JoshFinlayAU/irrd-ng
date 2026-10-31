//! `irrd-ng import`: the one-shot migration from an IRRd 4.5 database.
//!
//!   irrd-ng import --from-postgres <dsn> [--store <path>] [--batch-rows <n>]
//!                 [--write-batch-rows <n>]
//!
//! Reads the v4 database in one read-only snapshot and upserts every row
//! into the store, creating it if needed. The store is `--store`, else
//! `IRRD_NG_STORE_PATH`, else `/var/lib/irrd-ng`, as for every tool. Safe to re-run: a
//! second run over the same store changes nothing and duplicates nothing.

use std::ffi::OsString;
use std::process::ExitCode;
use std::time::Instant;

use import_v4::{Options, StoreSink};
use store::{Store, StoreOptions, StoreSettings};

use crate::messages;

/// The label of the import's whole-store load marker.
const WHOLE_STORE_LABEL: &str = "<all>";

struct Args {
    dsn: String,
    store: std::path::PathBuf,
    batch_rows: usize,
    write_rows: usize,
}

fn parse(args: &[OsString]) -> Result<Args, String> {
    let mut dsn = None;
    let mut store = None;
    let mut batch_rows = import_v4::DEFAULT_BATCH_ROWS;
    let mut write_rows = import_v4::to_store::WRITE_BATCH_ROWS;
    let mut it = args
        .iter()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned());
    while let Some(arg) = it.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_owned(), Some(v.to_owned())),
            _ => (arg.clone(), None),
        };
        let mut value = || {
            inline
                .clone()
                .or_else(|| it.next())
                .ok_or_else(|| messages::import_missing_value(&flag))
        };
        match flag.as_str() {
            "--from-postgres" => dsn = Some(value()?),
            "--store" => store = Some(std::path::PathBuf::from(value()?)),
            "--batch-rows" => {
                let v = value()?;
                batch_rows = v
                    .parse()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| messages::import_bad_int("--batch-rows", &v))?;
            }
            "--write-batch-rows" => {
                let v = value()?;
                write_rows = v
                    .parse()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| messages::import_bad_int("--write-batch-rows", &v))?;
            }
            "-h" | "--help" => return Err(String::new()),
            other => return Err(messages::import_unknown_arg(other)),
        }
    }
    Ok(Args {
        dsn: dsn.ok_or_else(|| messages::import_required("--from-postgres"))?,
        store: store.unwrap_or_else(crate::settings::store_path),
        batch_rows,
        write_rows,
    })
}

pub(crate) fn run(args: &[OsString]) -> ExitCode {
    let args = match parse(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{}", messages::IMPORT_USAGE);
            if e.is_empty() {
                return ExitCode::SUCCESS;
            }
            eprintln!("irrd-ng import: error: {e}");
            return ExitCode::from(2);
        }
    };
    crate::logging::init_stderr();
    match import(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}", messages::import_failed(&format!("{e:#}")));
            ExitCode::from(1)
        }
    }
}

fn import(args: &Args) -> anyhow::Result<()> {
    let start = Instant::now();
    tracing::info!(
        "{}",
        import_v4::messages::connecting(&import_v4::describe(&args.dsn))
    );
    let mut client = import_v4::connect(&args.dsn)?;
    // Bulk-load mode: no sync per commit, one at the end. The whole-store
    // marker is durable while the import runs, so a store whose import was
    // killed refuses to open instead of serving partial data.
    let options = StoreOptions {
        bulk_load: true,
        ..StoreOptions::new(&args.store)
    };
    let store = Store::open(&options, StoreSettings::default())?;
    let load = store.begin_whole_store_load(WHOLE_STORE_LABEL)?;
    let mut sink = StoreSink::with_batch_rows(&store, args.write_rows);
    let stats = import_v4::import(
        &mut client,
        &mut sink,
        &Options {
            batch_rows: args.batch_rows,
        },
    )?;
    load.finish()?;
    for (table, n) in &stats.tables {
        println!("{table}\t{n}");
    }
    println!(
        "{}",
        messages::import_summary(
            stats.total(),
            sink.written(),
            stats.serial_global_last_value,
            start.elapsed().as_secs_f64()
        )
    );
    Ok(())
}
