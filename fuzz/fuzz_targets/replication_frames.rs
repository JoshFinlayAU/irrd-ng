//! Replication frames, before and after the handshake, and the log entries
//! and snapshot rows they carry.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    replication::fuzzing::decode(data);
});
