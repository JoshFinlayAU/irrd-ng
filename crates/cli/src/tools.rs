//! The table of tools the multicall binary answers to.
//!
//! The twelve names are the console scripts IRRd 4.5.4 installs (its
//! `pyproject.toml`), plus `import` for the v4 PostgreSQL migration and
//! `migrate-check`, its pre-flight.

use std::ffi::OsString;
use std::process::ExitCode;

use crate::db_tools;

pub(crate) type Tool = fn(&[OsString]) -> ExitCode;

const TOOLS: &[(&str, Tool)] = &[
    ("irrd", crate::daemon::run),
    ("irrdctl", crate::mirror_tools::irrdctl),
    ("irrd_submit_email", crate::submit_tools::submit_email),
    ("irrd_database_upgrade", db_tools::database_upgrade),
    ("irrd_database_downgrade", db_tools::database_downgrade),
    ("irrd_load_database", db_tools::load_database),
    ("irrd_update_database", db_tools::update_database),
    (
        "irrd_set_last_modified_auth",
        crate::submit_tools::set_last_modified_auth,
    ),
    ("irrd_expire_journal", crate::serving_tools::expire_journal),
    (
        "irrd_mirror_force_reload",
        crate::mirror_tools::force_reload,
    ),
    ("irr_rpsl_submit", crate::rpsl_submit::run),
    ("irrd_load_pgp_keys", crate::submit_tools::load_pgp_keys),
    ("import", crate::import::run),
    ("migrate-check", crate::migrate_check::run),
];

/// Tools only reachable as `irrd-ng <tool>`, not listed in the usage.
const HIDDEN: &[(&str, Tool)] = &[
    ("export-jsonl", db_tools::export_jsonl),
    ("store-info", db_tools::store_info),
    ("run-export", crate::serving_tools::run_export),
    ("run-job", crate::job_tool::run_job),
];

pub(crate) fn lookup(name: &str) -> Option<Tool> {
    TOOLS
        .iter()
        .chain(HIDDEN)
        .find(|(n, _)| *n == name)
        .map(|(_, t)| *t)
}

pub(crate) fn names() -> Vec<&'static str> {
    TOOLS.iter().map(|(n, _)| *n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_v4_console_script_is_dispatchable() {
        for name in [
            "irrd",
            "irrdctl",
            "irrd_submit_email",
            "irrd_database_upgrade",
            "irrd_database_downgrade",
            "irrd_load_database",
            "irrd_update_database",
            "irrd_set_last_modified_auth",
            "irrd_expire_journal",
            "irrd_mirror_force_reload",
            "irr_rpsl_submit",
            "irrd_load_pgp_keys",
        ] {
            assert!(
                lookup(name).is_some(),
                "{name} missing from the dispatch table"
            );
        }
    }

    #[test]
    fn unknown_names_are_rejected() {
        assert!(lookup("irrctl").is_none());
    }
}
