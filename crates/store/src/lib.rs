//! LMDB schema, secondary indexes, journal and migrations.
//!
//! This is the only crate permitted to use `unsafe`. Every `unsafe` block
//! carries a `// SAFETY:` comment, enforced by clippy.

pub mod messages;
