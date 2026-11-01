//! `irrd-ng import`: the one-shot migration from an IRRd 4.5 database.
//!
//!   irrd-ng import --from-postgres <dsn> [--store <path>] [--batch-rows <n>]
//!                 [--write-batch-rows <n>] [--no-load-pgp-keys]
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
    /// Fill the PGP keyring from every key-cert; off with
    /// `--no-load-pgp-keys`.
    load_pgp_keys: bool,
}

fn parse(args: &[OsString]) -> Result<Args, String> {
    let mut dsn = None;
    let mut store = None;
    let mut batch_rows = import_v4::DEFAULT_BATCH_ROWS;
    let mut write_rows = import_v4::to_store::WRITE_BATCH_ROWS;
    let mut load_pgp_keys = true;
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
            "--load-pgp-keys" => load_pgp_keys = true,
            "--no-load-pgp-keys" => load_pgp_keys = false,
            "-h" | "--help" => return Err(String::new()),
            other => return Err(messages::import_unknown_arg(other)),
        }
    }
    Ok(Args {
        dsn: dsn.ok_or_else(|| messages::import_required("--from-postgres"))?,
        store: store.unwrap_or_else(crate::settings::store_path),
        batch_rows,
        write_rows,
        load_pgp_keys,
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
    let mut load_started = false;
    match import(&args, &mut load_started) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}", messages::import_failed(&format!("{e:#}")));
            if load_started {
                // The whole-store marker stays set: the store refuses to
                // open until it is imported again.
                eprintln!("{}", messages::import_store_incomplete(&args.store));
            }
            ExitCode::from(1)
        }
    }
}

fn import(args: &Args, load_started: &mut bool) -> anyhow::Result<()> {
    let start = Instant::now();
    tracing::info!(
        "{}",
        import_v4::messages::connecting(&import_v4::describe(&args.dsn))
    );
    let mut client = import_v4::connect(&args.dsn)?;
    import_v4::check_source(&mut client)?;
    // Bulk-load mode: no sync per commit, one at the end. The whole-store
    // marker is durable while the import runs, so a store whose import was
    // killed refuses to open instead of serving partial data.
    let options = StoreOptions {
        bulk_load: true,
        ..StoreOptions::new(&args.store)
    };
    let store = Store::open(&options, StoreSettings::default())?;
    let load = store.begin_whole_store_load(WHOLE_STORE_LABEL)?;
    *load_started = true;
    let mut sink = StoreSink::with_batch_rows(&store, args.write_rows);
    let stats = import_v4::import(
        &mut client,
        &mut sink,
        &Options {
            batch_rows: args.batch_rows,
        },
    )?;
    // The only step after the load: flush everything to disk, then clear
    // the load marker. Its time is reported on its own.
    tracing::info!("{}", messages::import_syncing());
    let sync_start = Instant::now();
    load.finish()?;
    tracing::info!(
        "{}",
        messages::import_synced(sync_start.elapsed().as_secs_f64())
    );
    let keys = if args.load_pgp_keys {
        Some(load_keyring_from_keycerts(&store)?)
    } else {
        None
    };
    for (table, n) in &stats.tables {
        println!(
            "{}",
            messages::import_table_line(table, *n, sink.deleted().get(table))
        );
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
    if let Some(keys) = keys {
        println!("{}", messages::import_keyring(keys));
    }
    Ok(())
}

/// v4 keeps its PGP keyring in a GnuPG home directory, outside the
/// database, so the import cannot copy it. Instead every stored key-cert
/// is parsed strictly, which imports its key as `irrd_load_pgp_keys` does
/// per source, so PGP signed submissions keep working straight after the
/// migration, as they did on v4. `--no-load-pgp-keys` leaves the keyring
/// empty, as on a v4 moved to a new host. Returns the number of keys in
/// the keyring.
fn load_keyring_from_keycerts(store: &Store) -> anyhow::Result<usize> {
    let texts: Vec<String> = {
        let r = store.read()?;
        let v = r.view();
        let mut out = Vec::new();
        for source in v.object_sources()? {
            for item in v.objects(Some(&source), Some("key-cert"))? {
                out.push(item?.1.object_text.to_owned());
            }
        }
        out
    };
    let settings = rpsl::RpslSettings::default();
    let keyring = nrtm::keyring::load_keyring(store);
    for text in &texts {
        let _ = rpsl::rpsl_object_from_text(
            text,
            &rpsl::ParseOptions {
                strict: true,
                default_source: None,
                settings: &settings,
                keyring: &keyring,
            },
        );
    }
    nrtm::keyring::save_keyring(store, &keyring);
    Ok(keyring.fingerprints().len())
}
