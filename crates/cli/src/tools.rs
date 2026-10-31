//! The table of tools the multicall binary answers to.
//!
//! The twelve names are the console scripts IRRd 4.5.4 installs (its
//! `pyproject.toml`), plus `import` for the v4 PostgreSQL migration.

use std::ffi::OsString;
use std::process::ExitCode;

use crate::{db_tools, messages};

pub(crate) type Tool = fn(&[OsString]) -> ExitCode;

const TOOLS: &[(&str, Tool)] = &[
    ("irrd", not_implemented),
    ("irrdctl", not_implemented),
    ("irrd_submit_email", not_implemented),
    ("irrd_database_upgrade", db_tools::database_upgrade),
    ("irrd_database_downgrade", db_tools::database_downgrade),
    ("irrd_load_database", db_tools::load_database),
    ("irrd_update_database", db_tools::update_database),
    ("irrd_set_last_modified_auth", not_implemented),
    ("irrd_expire_journal", not_implemented),
    ("irrd_mirror_force_reload", not_implemented),
    ("irr_rpsl_submit", not_implemented),
    ("irrd_load_pgp_keys", not_implemented),
    ("import", not_implemented),
];

/// Tools only reachable as `irrd-ng <tool>`, not listed in the usage.
const HIDDEN: &[(&str, Tool)] = &[("export-jsonl", db_tools::export_jsonl)];

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

fn not_implemented(args: &[OsString]) -> ExitCode {
    let name = args
        .first()
        .map(|a| a.to_string_lossy())
        .unwrap_or_default();
    eprintln!("{}", messages::not_implemented(&name));
    ExitCode::from(1)
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
