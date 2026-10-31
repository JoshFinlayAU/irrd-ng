//! Read a whole v4 database through the importer into a sink that only
//! counts, to measure the reading side on its own.
//!
//!   read_bench <dsn> [batch_rows]

use std::convert::Infallible;
use std::time::Instant;

use import_v4::{Batch, Options, Sink};

#[derive(Default)]
struct Count(u64, u64);

impl Sink for Count {
    type Error = Infallible;

    fn write(&mut self, batch: Batch) -> Result<(), Infallible> {
        self.0 += batch.len() as u64;
        if let Batch::RpslObjects(v) = &batch {
            self.1 += v.iter().map(|o| o.object_text.len() as u64).sum::<u64>();
        }
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let dsn = args.next().ok_or("usage: read_bench <dsn> [batch_rows]")?;
    let batch_rows = args
        .next()
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(import_v4::DEFAULT_BATCH_ROWS);
    let start = Instant::now();
    let mut client = import_v4::connect(&dsn)?;
    let mut sink = Count::default();
    let stats = import_v4::import(&mut client, &mut sink, &Options { batch_rows })?;
    for (table, n) in &stats.tables {
        println!("{table}\t{n}");
    }
    println!(
        "total\t{}\tobject_text_bytes\t{}\tsecs\t{:.1}",
        sink.0,
        sink.1,
        start.elapsed().as_secs_f64()
    );
    Ok(())
}
