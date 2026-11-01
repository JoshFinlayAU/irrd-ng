//! `irrd.yaml`: YAML loading and every configuration check.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = config::check_source_with_fs("irrd.yaml", Ok(data.to_vec()), &|_| true);
});
