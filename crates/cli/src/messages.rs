//! User-facing strings for the multicall dispatcher.
//!
//! Strings that v4 itself prints belong to each tool and are copied verbatim
//! from the pinned v4 source. These ones exist only in irrd-ng, because v4
//! installs separate scripts and has no dispatcher.

pub(crate) fn usage(tools: &[&str]) -> String {
    format!(
        "usage: irrd-ng <tool> [args...]\n\ntools: {}",
        tools.join(", ")
    )
}

pub(crate) fn unknown_tool(name: &str) -> String {
    format!("irrd-ng: unknown tool name {name:?}")
}

pub(crate) fn not_implemented(name: &str) -> String {
    format!("{name}: not implemented yet")
}

pub(crate) const IMPORT_USAGE: &str =
    "usage: irrd-ng import --from-postgres <dsn> --store <path> [--batch-rows <n>]";

pub(crate) fn import_missing_value(flag: &str) -> String {
    format!("argument {flag}: expected one argument")
}

pub(crate) fn import_required(flag: &str) -> String {
    format!("the following arguments are required: {flag}")
}

pub(crate) fn import_unknown_arg(arg: &str) -> String {
    format!("unrecognized arguments: {arg}")
}

pub(crate) fn import_bad_batch(v: &str) -> String {
    format!("argument --batch-rows: invalid positive int value: {v:?}")
}

pub(crate) fn import_failed(err: &str) -> String {
    format!("Import from IRRd v4 failed: {err}")
}

pub(crate) fn import_summary(read: u64, written: u64, serial_global: i64, secs: f64) -> String {
    format!(
        "Imported {read} rows ({written} written), serial_global continues after \
         {serial_global}, in {secs:.1}s"
    )
}
