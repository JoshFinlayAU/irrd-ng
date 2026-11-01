//! `/v1/submit/` and `/v1/suspension/` bodies and the metadata header.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = auth::api::json_loads(data) {
        let _ = auth::api::validate_change_submission(&v);
        let _ = auth::api::validate_suspension_submission(&v);
    }
    let _ = auth::api::parse_metadata_header(Some(data));
});
