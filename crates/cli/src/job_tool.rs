//! `irrd-ng run-job`: run one of the scheduler's status jobs once, in the
//! foreground, as the daemon's scheduler would start it. irrd-ng only (v4
//! has no such tool; its harness calls the runner classes from Python).
//! The parity harness uses it to step both servers through the same
//! changes.

use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::Arc;

use config::Configuration;
use store::{Store, StoreOptions};

use crate::argparse::{Opt, Parsed, Parser};
use crate::{logging, messages, settings};

const RUN_JOB: Parser = Parser {
    prog: "irrd-ng run-job",
    usage: "usage: irrd-ng run-job [-h] [--config CONFIG_FILE_PATH] job\n",
    help: "usage: irrd-ng run-job [-h] [--config CONFIG_FILE_PATH] job\n\nRun one scheduled job once: roa-import (ROAImportRunner), scopefilter\n(ScopeFilterUpdateRunner) or route-preference (RoutePreferenceUpdateRunner).\n\npositional arguments:\n  job                   the job to run\n\noptions:\n  -h, --help            show this help message and exit\n  --config CONFIG_FILE_PATH\n                        use a different IRRd config file (default:\n                        /etc/irrd.yaml)\n",
    options: &[Opt {
        flag: "--config",
        dest: "config_file_path",
        required: false,
        int: false,
        store_true: false,
    }],
    positionals: &["job"],
};

/// `irrd-ng run-job`
pub(crate) fn run_job(args: &[OsString]) -> ExitCode {
    let a = match RUN_JOB.parse(args.get(1..).unwrap_or_default()) {
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
    let store = match Store::open(
        &StoreOptions::new(settings::store_path()),
        settings::store_settings(&cfg),
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    store.set_route_preference_hook(Some(rpki::route_preference_hook));
    let mirror = Arc::new(settings::mirror_settings(&cfg));
    let job = a.get("job").map(String::as_str).unwrap_or_default();
    use nrtm::mirror::status_jobs as jobs;
    match job {
        "roa-import" => {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(1);
                }
            };
            rt.block_on(jobs::run_roa_import(store, mirror));
        }
        "scopefilter" => jobs::run_scopefilter_update(&store, &mirror),
        "route-preference" => jobs::run_route_preference_update(&store),
        other => {
            eprintln!("{}", messages::unknown_job(other));
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}
