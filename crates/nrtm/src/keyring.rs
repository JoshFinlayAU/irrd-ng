//! The store-backed PGP keyring (v4's `auth.gnupg_keyring`).
//!
//! v4 imports every key-cert it parses strictly into one GnuPG keyring that
//! lives outside its database transactions: a key stays imported even when
//! the transaction that parsed it rolls back. irrd-ng keeps the keyring in
//! the store's `pgp_keyring` table. [`StoreKeyring`] loads it, lends it to
//! the parsers, and writes the keys they imported back in a transaction of
//! its own when it is dropped, whatever happened to the run.

use std::ops::Deref;

use rpsl::Keyring;
use store::Store;

/// Log target for keyring persistence failures.
const LOG_TARGET: &str = "irrd_ng.keyring";

/// Read the keyring from the store. A store that cannot be read gives an
/// empty keyring, as a missing GnuPG home directory does in v4.
pub fn load_keyring(store: &Store) -> Keyring {
    match store.read().and_then(|r| r.view().pgp_keyring()) {
        Ok(entries) => Keyring::from_entries(entries),
        Err(e) => {
            tracing::error!(target: LOG_TARGET, "unable to read the PGP keyring: {e}");
            Keyring::new()
        }
    }
}

/// Write the keys imported into `keyring` since it was loaded (or last
/// saved) to the store.
pub fn save_keyring(store: &Store, keyring: &Keyring) {
    let dirty = keyring.dirty_entries();
    if dirty.is_empty() {
        return;
    }
    let result = store.write(move |tx| {
        for (fpr, bytes) in &dirty {
            tx.put_pgp_key(fpr, bytes)?;
        }
        Ok(())
    });
    if let Err(e) = result {
        tracing::error!(target: LOG_TARGET, "unable to save the PGP keyring: {e}");
    }
}

/// A keyring loaded from the store that saves its imports when dropped.
#[derive(Debug)]
pub struct StoreKeyring {
    store: Store,
    keyring: Keyring,
}

impl StoreKeyring {
    /// Load the keyring of `store`.
    pub fn load(store: &Store) -> Self {
        StoreKeyring {
            store: store.clone(),
            keyring: load_keyring(store),
        }
    }
}

impl Deref for StoreKeyring {
    type Target = Keyring;

    fn deref(&self) -> &Keyring {
        &self.keyring
    }
}

impl Drop for StoreKeyring {
    fn drop(&mut self) {
        save_keyring(&self.store, &self.keyring);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpsl::{ParseOptions, RpslSettings, rpsl_object_from_text};
    use store::{StoreOptions, StoreSettings};

    const KEY_CERT: &str = include_str!("../../rpsl/tests/pgp/key-cert-80F238C6.txt");

    #[test]
    fn imports_survive_the_run_that_made_them() {
        let dir = tempfile::tempdir().expect("dir");
        let store = Store::open(&StoreOptions::new(dir.path()), StoreSettings::default())
            .expect("store");
        {
            let keyring = StoreKeyring::load(&store);
            assert!(keyring.fingerprints().is_empty());
            let settings = RpslSettings::default();
            let obj = rpsl_object_from_text(
                KEY_CERT.trim(),
                &ParseOptions {
                    strict: true,
                    default_source: None,
                    settings: &settings,
                    keyring: &keyring,
                },
            )
            .expect("parse");
            assert!(!obj.messages().has_errors());
        }
        let again = load_keyring(&store);
        assert_eq!(
            again.fingerprints(),
            vec!["86261D8DBEBDA4F54692D64DA8383BA780F238C6".to_owned()]
        );
    }
}
