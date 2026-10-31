//! LMDB schema, secondary indexes, journal and migrations.
//!
//! The store holds everything IRRd v4 keeps in PostgreSQL, one table per v4
//! table ([`model`] has the row types, named after v4's columns), plus
//! secondary indexes for the queries v4 answers with SQL ([`index`]).
//!
//! - [`Store::open`] opens or creates the environment, migrating an older
//!   schema ([`SCHEMA_VERSION`]).
//! - [`Store::read`] starts a read transaction; [`ReadView`] has the
//!   queries. Records are read zero-copy.
//! - [`Store::write`] runs a closure on the single writer thread as one v4
//!   database transaction. [`WriteTx`] has v4's `DatabaseHandler` methods
//!   (journal and `database_status` semantics included) and a raw row API
//!   for the v4 importer (`put_*`).
//! - [`export`] writes the canonical JSONL export used by the three-way
//!   load check.
//!
//! This is the only crate permitted to use `unsafe`. Every `unsafe` block
//! carries a `// SAFETY:` comment, enforced by clippy.

pub mod env;
mod error;
pub mod export;
pub mod index;
mod keys;
pub mod messages;
pub mod model;
mod query;
pub mod read;
pub mod records;
mod settings;
mod store;
pub mod write;

pub use env::{SCHEMA_VERSION, StoreOptions, TABLE_NAMES};
pub use error::{Result, StoreError};
pub use index::{LOOKUP_FIELD_NAMES, OriginRoute, Space};
pub use model::*;
pub use read::{ObjectId, ReadTx, ReadView};
pub use records::{JournalEntryRef, RpslObjectRef, SetMembers};
pub use settings::{SourceSettings, StoreSettings};
pub use store::{BulkLoad, Store, StoreInfo};
pub use write::{AuthTable, ChangedObjects, Pruned, RoutePreferenceHook, WriteTx};
