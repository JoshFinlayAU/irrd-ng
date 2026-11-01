//! RPSL objects, as submitted or mirrored: strict and non-strict parsing.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rpsl::{Keyring, ParseOptions, RpslSettings};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let settings = RpslSettings::default();
    let keyring = Keyring::new();
    for strict in [false, true] {
        let options = ParseOptions {
            strict,
            default_source: Some("TEST"),
            settings: &settings,
            keyring: &keyring,
        };
        if let Ok(o) = rpsl::rpsl_object_from_text(text, &options) {
            let _ = o.parsed_data();
        }
    }
    let _ = rpsl::split_paragraphs_rpsl(text, true);
    let _ = rpsl::split_rpsl_file(data);
});
