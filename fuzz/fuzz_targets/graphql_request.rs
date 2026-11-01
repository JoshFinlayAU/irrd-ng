//! `/graphql/` JSON request bodies: the JSON decoder, then the query's
//! parsing and validation against IRRd's schema.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    http::fuzzing::graphql(data);
});
