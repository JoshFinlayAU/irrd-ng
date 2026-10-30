//! Parse an RPSL file the way v4's importers do and print a summary.
//!
//! `cargo run --release -p rpsl --example rpsl_parse -- [--strict] FILE...`
//!
//! Useful as a quick throughput check and to see which objects v4 would
//! reject; it reports objects, errors, unknown classes and elapsed time.

use std::process::ExitCode;
use std::time::Instant;

use rpsl::{Keyring, ParseError, ParseOptions, RpslSettings, rpsl_object_from_text};

fn main() -> ExitCode {
    let mut strict = false;
    let mut files = Vec::new();
    for arg in std::env::args().skip(1) {
        if arg == "--strict" {
            strict = true;
        } else {
            files.push(arg);
        }
    }
    if files.is_empty() {
        eprintln!("usage: rpsl_parse [--strict] FILE...");
        return ExitCode::from(2);
    }
    let settings = RpslSettings::default();
    let keyring = Keyring::new();
    let options = ParseOptions {
        strict,
        default_source: None,
        settings: &settings,
        keyring: &keyring,
    };
    for file in files {
        let bytes = match std::fs::read(&file) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{file}: {e}");
                return ExitCode::FAILURE;
            }
        };
        let start = Instant::now();
        let paragraphs = rpsl::split_rpsl_file(&bytes);
        let split = start.elapsed();
        let (mut ok, mut errors, mut unknown, mut uncaught) = (0usize, 0usize, 0usize, 0usize);
        for p in &paragraphs {
            match rpsl_object_from_text(rpsl::text::py_strip(p), &options) {
                Ok(obj) if obj.messages().has_errors() => errors += 1,
                Ok(_) => ok += 1,
                Err(ParseError::UnknownClass { .. }) => unknown += 1,
                Err(ParseError::Uncaught(_)) => uncaught += 1,
            }
        }
        let total = start.elapsed();
        println!(
            "{file}: {} paragraphs, {ok} ok, {errors} with errors, {unknown} unknown class, {uncaught} uncaught; split {split:.2?}, total {total:.2?} ({:.0} objects/s)",
            paragraphs.len(),
            paragraphs.len() as f64 / total.as_secs_f64().max(1e-9)
        );
    }
    ExitCode::SUCCESS
}
