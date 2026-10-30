//! Differential test against IRRd v4 on real registry data.
//!
//! Set `IRRD_NG_ORACLE_DIR` to a directory of `<SOURCE>.rpsl.jsonl` files made
//! by `parity/oracle/gen.sh`, and `IRRD_NG_FIXTURE_DIR` to the matching raw
//! `<SOURCE>.db` fixtures. Every paragraph must split, parse and render
//! exactly as v4 does in both strict and non-strict mode. Without the
//! variables the test is skipped: the dumps are real data and never in git.

#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::path::PathBuf;

#[test]
fn rpsl_matches_v4_oracle() {
    let (Some(oracle_dir), Some(fixture_dir)) = (
        std::env::var_os("IRRD_NG_ORACLE_DIR"),
        std::env::var_os("IRRD_NG_FIXTURE_DIR"),
    ) else {
        println!("skipped: IRRD_NG_ORACLE_DIR and IRRD_NG_FIXTURE_DIR are not set");
        return;
    };
    let oracle_dir = PathBuf::from(oracle_dir);
    let fixture_dir = PathBuf::from(fixture_dir);
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&oracle_dir)
        .unwrap_or_else(|e| panic!("{}: {e}", oracle_dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.to_string_lossy().ends_with(".rpsl.jsonl"))
        .collect();
    entries.sort();
    assert!(
        !entries.is_empty(),
        "no *.rpsl.jsonl in {}",
        oracle_dir.display()
    );

    let max_examples: usize = std::env::var("IRRD_NG_ORACLE_EXAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let mut failed = false;
    println!(
        "{:<14} {:>10} {:>12} {:>12} {:>10}",
        "source", "paragraphs", "strict-exact", "relaxed-exact", "mismatches"
    );
    for path in entries {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".rpsl.jsonl"))
            .unwrap_or_default()
            .to_owned();
        let db_path = fixture_dir.join(format!("{name}.db"));
        let db = std::fs::read(&db_path).unwrap_or_else(|e| panic!("{}: {e}", db_path.display()));
        let rows = common::read_jsonl(&path);
        let tally = common::compare_file(&db, &rows, max_examples);
        println!(
            "{:<14} {:>10} {:>12} {:>12} {:>10}",
            name,
            tally.paragraphs,
            tally.exact[0],
            tally.exact[1],
            tally.mismatches()
        );
        for (field, count) in &tally.by_field {
            println!("    {field}: {count}");
        }
        for e in &tally.examples {
            println!("{e}");
        }
        if tally.mismatches() > 0 {
            failed = true;
        }
    }
    assert!(!failed, "irrd-ng differs from the v4 oracle, see above");
}
