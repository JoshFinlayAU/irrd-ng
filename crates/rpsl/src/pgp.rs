//! Placeholder; replaced by the sequoia implementation.

use crate::fields::Uncaught;

/// A PGP keyring.
#[derive(Debug, Default)]
pub struct Keyring {}

pub(crate) struct ImportResult {
    pub(crate) fingerprints: Vec<String>,
    pub(crate) results: Vec<String>,
}

impl Keyring {
    /// An empty keyring.
    pub fn new() -> Self {
        Keyring {}
    }

    pub(crate) fn import_keys(&self, _data: &str) -> Result<ImportResult, Uncaught> {
        Ok(ImportResult {
            fingerprints: Vec::new(),
            results: Vec::new(),
        })
    }

    pub(crate) fn uids(&self, _fingerprint: &str) -> Vec<String> {
        Vec::new()
    }
}
