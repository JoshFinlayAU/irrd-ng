//! Differential test against committed v4 oracle output for the synthetic
//! corpus in `parity/corpus/rpsl/` (see `make_corpus.py` and `regen.sh`
//! there), and for v4's own `irrd/utils/rpsl_samples.py`.

mod common;

use std::path::{Path, PathBuf};

use rpsl::{Keyring, RpslSettings};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../parity/corpus/rpsl")
}

fn report(name: &str, tally: &common::Tally) -> bool {
    println!(
        "{name:<14} {:>5} paragraphs, strict exact {:>5}, relaxed exact {:>5}, mismatches {}",
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
    tally.mismatches() == 0
}

#[test]
fn synthetic_corpus_matches_v4() {
    let dir = corpus_dir();
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_suffix(".db"))
                .map(str::to_owned)
        })
        .collect();
    names.sort();
    assert!(names.len() >= 8, "corpus files missing from {}", dir.display());
    let mut ok = true;
    for name in names {
        let db = std::fs::read(dir.join(format!("{name}.db"))).unwrap_or_else(|e| panic!("{name}: {e}"));
        let rows = common::read_jsonl(&dir.join(format!("expected.{name}.jsonl")));
        let tally = common::compare_file(&db, &rows, 10);
        ok &= report(&name, &tally);
    }
    assert!(ok, "irrd-ng differs from v4 on the synthetic corpus, see above");
}

#[test]
fn rpsl_samples_match_v4() {
    let rows = common::read_jsonl(&corpus_dir().join("expected.samples.jsonl"));
    assert!(rows.len() >= 25);
    let settings = RpslSettings::default();
    let keyring = Keyring::new();
    let mut tally = common::Tally::default();
    for row in &rows {
        let text = row["text"].as_str().unwrap_or_default();
        common::compare_row(row, text, &settings, &keyring, &mut tally, 10);
    }
    assert!(report("samples", &tally), "irrd-ng differs from v4 on rpsl_samples.py");
}
