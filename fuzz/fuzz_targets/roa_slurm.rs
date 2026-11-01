//! ROA JSON and SLURM files: the two parts are split at the first 0xff
//! byte.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (roa, slurm) = match data.iter().position(|b| *b == 0xff) {
        Some(i) => (&data[..i], Some(&data[i + 1..])),
        None => (data, None),
    };
    let roa = String::from_utf8_lossy(roa);
    let slurm = slurm.map(String::from_utf8_lossy);
    let _ = rpki::importer::RoaImport::parse(&roa, slurm.as_deref(), None);
});
