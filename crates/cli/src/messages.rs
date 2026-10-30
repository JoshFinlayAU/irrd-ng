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
