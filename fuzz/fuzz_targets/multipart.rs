//! `multipart/form-data` GraphQL requests: content type parameters on the
//! first line, then the body.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    http::fuzzing::multipart(data);
});
