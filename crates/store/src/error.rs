//! Store errors.

use std::path::{Path, PathBuf};

use crate::messages;

/// Result alias for the store.
pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// An LMDB error.
    #[error("LMDB error: {0}")]
    Lmdb(#[from] heed::Error),
    /// The environment could not be opened.
    #[error("{}", messages::open_failed(.path, .source))]
    Open {
        /// The store directory.
        path: PathBuf,
        /// The cause.
        source: heed::Error,
    },
    /// A file system error.
    #[error("{}: {}", .0.display(), .1)]
    Io(PathBuf, std::io::Error),
    /// A record could not be encoded or decoded.
    #[error("record encoding error: {0}")]
    Codec(#[from] postcard::Error),
    /// A record or key had an unexpected shape.
    #[error("corrupt store: unexpected {0}")]
    Corrupt(&'static str),
    /// Opened read-only, but the store has never been written.
    #[error("{}", messages::not_initialised(.0))]
    NotInitialised(PathBuf),
    /// The store was written by a newer irrd-ng.
    #[error("{}", messages::schema_too_new(*.found, *.supported))]
    SchemaTooNew {
        /// Version on disk.
        found: u32,
        /// Version this build supports.
        supported: u32,
    },
    /// The store needs migrating, and is open read-only.
    #[error("{}", messages::schema_too_old(*.found, *.supported))]
    SchemaTooOld {
        /// Version on disk.
        found: u32,
        /// Version this build supports.
        supported: u32,
    },
    /// No migration path exists.
    #[error("{}", messages::no_migration(*.from, *.to))]
    NoMigration {
        /// Version on disk.
        from: u32,
        /// Target version.
        to: u32,
    },
    /// A write was attempted on a read-only store, or with
    /// `readonly_standby` set (v4's message).
    #[error("{}", messages::READONLY_WRITE)]
    ReadOnly,
    /// A unique constraint v4's schema enforces was violated.
    #[error("{0}")]
    UniqueViolation(String),
    /// A NOT NULL constraint v4's schema enforces was violated.
    #[error("{0}")]
    NotNullViolation(String),
    /// v4 raises a `ValueError` here; the text is v4's.
    #[error("{0}")]
    ValueError(String),
    /// A bulk load was interrupted: the store may hold a partial source
    /// and is refused.
    #[error("{}", messages::load_incomplete(.path, .load_source))]
    LoadIncomplete {
        /// The store directory.
        path: PathBuf,
        /// The source that was being loaded.
        load_source: String,
    },
    /// The writer thread is gone.
    #[error("the store writer thread has stopped")]
    WriterGone,
    /// The caller's own error, returned from a write closure to roll back.
    #[error("{0}")]
    Aborted(String),
}

impl StoreError {
    pub(crate) fn open(path: &Path, source: heed::Error) -> Self {
        StoreError::Open {
            path: path.to_path_buf(),
            source,
        }
    }

    /// Whether this is LMDB's "map full".
    pub(crate) fn is_map_full(&self) -> bool {
        matches!(
            self,
            StoreError::Lmdb(heed::Error::Mdb(heed::MdbError::MapFull))
        )
    }
}
