//! NRTMv3 streams from a mirror upstream.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = nrtm::mirror::nrtm3::parse_nrtm_stream("TEST", &text);
});
