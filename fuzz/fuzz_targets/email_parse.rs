//! E-mail submissions as `irrd_submit_email` reads them from stdin.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = auth::email_parser::decode_input(data);
    let keyring = rpsl::Keyring::new();
    if let Ok(parsed) = auth::email_parser::EmailParser::parse(&text, &keyring) {
        let _ = parsed;
    }
    for header in text.lines().take(8) {
        let _ = auth::email_parser::reply_addresses(header);
    }
});
