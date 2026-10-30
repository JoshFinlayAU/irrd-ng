//! The irrd-ng multicall binary.
//!
//! One executable is installed once and symlinked under every v4 tool name.
//! The name it was invoked as picks the tool, so `irrd`, `irrdctl` and the
//! `irrd_*` scripts keep the binary names, flags and exit codes operators
//! already use. Invoked as `irrd-ng`, the first argument names the tool
//! instead (`irrd-ng irrd_load_database ...`), plus the irrd-ng-only
//! `import` command.

use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod tools;

fn main() -> ExitCode {
    let mut args: Vec<OsString> = std::env::args_os().collect();
    let invoked = args
        .first()
        .and_then(|a| Path::new(a).file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("irrd-ng")
        .to_owned();

    let name = if invoked == "irrd-ng" {
        if args.len() < 2 {
            eprintln!(
                "usage: irrd-ng <tool> [args...]\n\ntools: {}",
                tools::names().join(", ")
            );
            return ExitCode::from(2);
        }
        args.remove(0);
        args[0].to_string_lossy().into_owned()
    } else {
        invoked
    };

    match tools::lookup(&name) {
        Some(tool) => tool(&args),
        None => {
            eprintln!("irrd-ng: unknown tool name {name:?}");
            ExitCode::from(2)
        }
    }
}
