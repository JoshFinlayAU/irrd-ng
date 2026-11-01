//! Client WebSocket frames for the event stream and GraphQL endpoints,
//! with and without `permessage-deflate`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    http::fuzzing::websocket(data);
});
