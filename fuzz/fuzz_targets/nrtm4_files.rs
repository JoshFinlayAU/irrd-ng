//! NRTMv4 files from a mirror upstream: the JWS envelope of an Update
//! Notification File and the keys it names, the file's JSON, and snapshot
//! and delta files as JSON sequences with their headers.
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use nrtm::mirror::nrtm4::{json, jsonseq, jws, types};

/// A P-256 public key for the JWS check. Test data only: no signature made
/// by its private key is ever trusted anywhere.
const KEY: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETo/La1S7xtX+s11hubAVa/OFIReZ
eTiG0keR1hgnCU06DATwo3IhcYPw4vDFHgGwHCaoGnz877YhLezP4HIh0A==
-----END PUBLIC KEY-----";

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 4 {
        0 => {
            if let Ok(key) = jws::eckey_from_str(KEY) {
                let _ = jws::jws_deserialize(rest, &key);
            }
        }
        1 => {
            let _ = jws::eckey_from_str(&String::from_utf8_lossy(rest));
        }
        2 => {
            let _ = types::validate_unf_at(rest, "TEST", 1_800_000_000);
            let _ = json::loads(rest);
        }
        _ => {
            let session = uuid::Uuid::nil();
            let mut reader = jsonseq::JsonSeqReader::new(Cursor::new(rest));
            let mut first = true;
            for _ in 0..1000 {
                let Some(Ok(item)) = reader.next_item() else {
                    break;
                };
                if first {
                    for kind in [types::HeaderKind::Snapshot, types::HeaderKind::Delta] {
                        let _ = types::validate_header(&item, kind, "TEST", &session, 3);
                    }
                    first = false;
                }
            }
        }
    }
});
