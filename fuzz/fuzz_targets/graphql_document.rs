//! GraphQL documents on their own: the parser and validation, without the
//! JSON envelope, so the fuzzer spends its time in the GraphQL grammar.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    http::fuzzing::graphql_document(text);
});
