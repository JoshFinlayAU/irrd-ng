//! Signature checks against the keyring, with the samples from v4's own
//! tests (`irrd/utils/tests/test_pgp.py`, `irrd/utils/rpsl_samples.py`):
//! the test key PGPKEY-80F238C6 and messages it signed.

#![allow(clippy::unwrap_used)]

use rpsl::{Keyring, ParseOptions, RpslSettings, rpsl_object_from_text};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/pgp/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

const FPR: &str = "86261D8DBEBDA4F54692D64DA8383BA780F238C6";

fn loaded_keyring() -> Keyring {
    let settings = RpslSettings::default();
    let keyring = Keyring::new();
    let obj = rpsl_object_from_text(
        fixture("key-cert-80F238C6.txt").trim(),
        &ParseOptions {
            strict: true,
            default_source: None,
            settings: &settings,
            keyring: &keyring,
        },
    )
    .unwrap();
    assert!(!obj.messages().has_errors());
    keyring
}

#[test]
fn detached_signature_verifies() {
    let k = loaded_keyring();
    let msg = fixture("test_valid_detached_signed_ascii.msg.txt") + "\n";
    let sig = fixture("test_valid_detached_signed_ascii.sig.txt");
    assert_eq!(
        k.verify_detached(msg.as_bytes(), sig.as_bytes()).as_deref(),
        Some(FPR)
    );
}

#[test]
fn detached_signature_over_other_text_fails() {
    let k = loaded_keyring();
    let msg = fixture("test_invalid_signature_detached_signed_ascii.msg.txt") + "\n";
    let sig = fixture("test_invalid_signature_detached_signed_ascii.sig.txt");
    assert_eq!(k.verify_detached(msg.as_bytes(), sig.as_bytes()), None);
}

#[test]
fn inline_signature_verifies() {
    let k = loaded_keyring();
    let msg = fixture("test_valid_inline_signed_ascii.0.txt");
    assert_eq!(k.verify_cleartext(msg.as_bytes()).as_deref(), Some(FPR));
    let signed = fixture("signed-person-update.txt");
    assert_eq!(k.verify_cleartext(signed.as_bytes()).as_deref(), Some(FPR));
}

#[test]
fn unknown_key_fails() {
    let k = Keyring::new();
    let msg = fixture("test_valid_inline_signed_ascii.0.txt");
    assert_eq!(k.verify_cleartext(msg.as_bytes()), None);
}

#[test]
fn keyring_round_trips_through_entries() {
    let k = loaded_keyring();
    let entries = k.dirty_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, FPR);
    assert!(k.dirty_entries().is_empty());
    let k2 = Keyring::from_entries(entries);
    assert_eq!(k2.fingerprints(), vec![FPR.to_owned()]);
    let msg = fixture("test_valid_inline_signed_ascii.0.txt");
    assert_eq!(k2.verify_cleartext(msg.as_bytes()).as_deref(), Some(FPR));
}

#[test]
fn cleartext_text_is_the_signed_text() {
    let k = loaded_keyring();
    let (fpr, text) = k
        .verify_cleartext_text(fixture("test_valid_inline_signed_ascii.0.txt").as_bytes())
        .unwrap();
    assert_eq!(fpr, FPR);
    assert_eq!(text, b"test\n1\n\n2\n\n3\n");
    // Text after the first signature block is not part of it.
    let appended = fixture("signed-person-update.txt")
        + "\nperson: EVIL\nsource: TEST\n\n-----BEGIN PGP SIGNATURE-----\n";
    let (_, text) = k.verify_cleartext_text(appended.as_bytes()).unwrap();
    assert!(text.ends_with(b"source: TEST"));
    assert!(!String::from_utf8_lossy(&text).contains("EVIL"));
}
