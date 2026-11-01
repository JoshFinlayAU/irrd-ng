//! Inline (cleartext) PGP signed submissions: the body that is processed
//! is the text the signature covers, and nothing appended after it
//! (DIV-007). Uses v4's test key PGPKEY-80F238C6 and messages it signed
//! (`irrd/utils/tests/test_pgp.py`, `irrd/utils/rpsl_samples.py`).

#![allow(clippy::unwrap_used)]

use auth::email_parser::{EmailParser, validate_pgp_signature};
use rpsl::{Keyring, ParseOptions, RpslSettings, rpsl_object_from_text};

const FPR: &str = "86261D8DBEBDA4F54692D64DA8383BA780F238C6";
const KEY_CERT: &str = include_str!("../../rpsl/tests/pgp/key-cert-80F238C6.txt");
const SIGNED_UPDATE: &str = include_str!("../../rpsl/tests/pgp/signed-person-update.txt");
const SIGNED_WITH_PREFIX: &str =
    include_str!("../../rpsl/tests/pgp/test_valid_inline_signed_ascii.0.txt");

/// The body v4 extracts from `signed-person-update.txt`.
const SIGNED_BODY: &str = "person: Test person changed by PGP signed update\n\
address: DashCare BV\n\
address: Amsterdam\n\
address: The Netherlands\n\
phone: +31 20 000 0000\n\
nic-hdl: PERSON-TEST\n\
mnt-by: TEST-MNT\n\
e-mail: email@example.com\n\
changed: changed@example.com 20190701 # comment\n\
source: TEST\n";

const INJECTED: &str =
    "\nperson: EVIL\nnic-hdl: EVIL-TEST\nsource: TEST\n\n-----BEGIN PGP SIGNATURE-----\n";

fn keyring() -> Keyring {
    let settings = RpslSettings::default();
    let keyring = Keyring::new();
    let obj = rpsl_object_from_text(
        KEY_CERT.trim(),
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

fn email(body: &str) -> String {
    format!(
        "From: Sasha <sasha@example.com>\nSubject: update\nMessage-ID: <x@example.com>\n\
         Content-Type: text/plain; charset=us-ascii\n\n{body}"
    )
}

#[test]
fn legitimate_signed_message_is_unchanged() {
    let k = keyring();
    assert_eq!(
        validate_pgp_signature(SIGNED_UPDATE, None, &k).unwrap(),
        (Some(SIGNED_BODY.to_owned()), Some(FPR.to_owned()))
    );
    // Unsigned text before the signed block is dropped, as in v4.
    assert_eq!(
        validate_pgp_signature(SIGNED_WITH_PREFIX, None, &k).unwrap(),
        (
            Some("test\n1\n\n2\n\n3\n\n".to_owned()),
            Some(FPR.to_owned())
        )
    );
    // Trailing text after the signature is dropped, as in v4.
    let trailing = format!("{SIGNED_UPDATE}\n-- \nmailing list footer\n");
    assert_eq!(
        validate_pgp_signature(&trailing, None, &k).unwrap(),
        (Some(SIGNED_BODY.to_owned()), Some(FPR.to_owned()))
    );
    // CRLF line endings, and trailing whitespace the signature does not
    // cover, give v4's body.
    let crlf = SIGNED_UPDATE.replace('\n', "\r\n");
    assert_eq!(
        validate_pgp_signature(&crlf, None, &k).unwrap(),
        (Some(SIGNED_BODY.to_owned()), Some(FPR.to_owned()))
    );
    let spaced = SIGNED_UPDATE.replace("source: TEST\n", "source: TEST  \t\n");
    assert_eq!(
        validate_pgp_signature(&spaced, None, &k).unwrap(),
        (
            Some(SIGNED_BODY.replace("source: TEST\n", "source: TEST  \t\n")),
            Some(FPR.to_owned())
        )
    );

    let parsed = EmailParser::parse(&email(SIGNED_UPDATE), &k).unwrap();
    assert_eq!(parsed.body.as_deref(), Some(SIGNED_BODY));
    assert_eq!(parsed.pgp_fingerprint.as_deref(), Some(FPR));
}

#[test]
fn tampered_signed_text_is_not_signed() {
    let k = keyring();
    let tampered = SIGNED_UPDATE.replace("Amsterdam", "Rotterdam");
    assert_eq!(
        validate_pgp_signature(&tampered, None, &k).unwrap(),
        (None, None)
    );
}

/// Objects appended after a genuine signature, followed by a second
/// `-----BEGIN PGP SIGNATURE-----` line: v4's greedy pattern extracts
/// them as part of the signed body.
#[test]
fn objects_appended_after_the_signature_are_not_signed() {
    let k = keyring();
    let attack = format!("{SIGNED_UPDATE}{INJECTED}");
    let (body, fpr) = validate_pgp_signature(&attack, None, &k).unwrap();
    assert_eq!(body.as_deref(), Some(SIGNED_BODY));
    assert_eq!(fpr.as_deref(), Some(FPR));

    let parsed = EmailParser::parse(&email(&attack), &k).unwrap();
    assert!(!parsed.body.as_deref().unwrap().contains("EVIL"));
    assert_eq!(parsed.body.as_deref(), Some(SIGNED_BODY));
}

/// The same, with the genuine armor line changed so the extraction
/// pattern does not see it as the end of the signed text: the extracted
/// body is not what the signature covers, so nothing is signed.
#[test]
fn signed_text_boundary_mismatch_is_not_signed() {
    let k = keyring();
    let attack = format!("{SIGNED_UPDATE}{INJECTED}").replacen(
        "\n-----BEGIN PGP SIGNATURE-----\n",
        "\n-----BEGIN PGP SIGNATURE----- \n",
        1,
    );
    let (body, fpr) = validate_pgp_signature(&attack, None, &k).unwrap();
    if fpr.is_some() {
        assert!(!body.unwrap_or_default().contains("EVIL"));
    }
    assert_eq!(fpr, None);
    // As an unsigned message, the whole body is processed without PGP
    // authentication.
    let parsed = EmailParser::parse(&email(&attack), &k).unwrap();
    assert_eq!(parsed.pgp_fingerprint, None);
}

/// Dash-escaped lines are compared unescaped but returned as v4 returns
/// them.
#[test]
fn dash_escaped_lines_are_compared_unescaped() {
    let k = keyring();
    // `- ` before a line the signer did not escape changes nothing the
    // signature covers once unescaped.
    let escaped = SIGNED_UPDATE.replace("source: TEST\n", "- source: TEST\n");
    let (body, fpr) = validate_pgp_signature(&escaped, None, &k).unwrap();
    assert_eq!(fpr.as_deref(), Some(FPR));
    assert_eq!(
        body.as_deref(),
        Some(
            SIGNED_BODY
                .replace("source: TEST\n", "- source: TEST\n")
                .as_str()
        )
    );
}
