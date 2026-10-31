//! Log output for the command-line tools: tracing events to stderr.
//! The daemon's v4-compatible logging (log.* settings) comes in Phase 9.

pub(crate) fn init() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_max_level(tracing::Level::INFO)
        .try_init();
}
