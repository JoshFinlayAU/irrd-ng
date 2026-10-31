//! The reader against v4's own export of the same database.
//!
//! Reads a v4 database through `import_v4::import`, renders every row with
//! `import_v4::canonical`, and requires the result to equal what
//! `parity/tools/export_v4.py` exported from that database, table by table,
//! byte for byte. Needs a harness database, so it runs only when both are
//! given (`parity/loadcheck/run.sh` sets them):
//!
//!   IRRD_NG_TEST_V4_DSN     postgresql://irrd:irrd@127.0.0.1:9432/v4_seeded
//!   IRRD_NG_TEST_V4_EXPORT  parity/.work/seeded/v4/export

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::PathBuf;

use import_v4::rows::{Cell, V4Table};
use import_v4::{Batch, Options, Sink, canonical};

/// A rendered row and the key export_v4.py sorts it by.
type SortedLine = (Vec<String>, Vec<u8>);

#[derive(Default)]
struct Collect {
    revision: String,
    finished: bool,
    serial_global: Option<i64>,
    tables: BTreeMap<&'static str, Vec<SortedLine>>,
}

/// export_v4.py's row order.
fn sort_key(table: &str, cells: &[(&str, Cell<'_>)]) -> Vec<String> {
    let get = |name: &str| -> String {
        let cell = cells
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, c)| *c)
            .unwrap_or(Cell::Null);
        match cell {
            Cell::Text(s) => s.to_owned(),
            Cell::Uuid(u) => u.hyphenated().to_string(),
            Cell::Int(n) => format!("{n:020}"),
            other => panic!("unexpected sort cell {other:?}"),
        }
    };
    match table {
        "rpsl_objects" => vec![get("source"), get("object_class"), get("rpsl_pk")],
        "rpsl_database_journal" => vec![get("serial_global")],
        "database_status" => vec![get("source")],
        "setting" => vec![get("name")],
        _ => vec![get("pk")],
    }
}

fn add<T: V4Table>(c: &mut Collect, rows: Vec<T>) {
    for row in rows {
        let cells = row.cells();
        let mut line = Vec::new();
        canonical::write_row(&mut line, &cells).unwrap();
        c.tables
            .entry(T::TABLE)
            .or_default()
            .push((sort_key(T::TABLE, &cells), line));
    }
}

impl Sink for Collect {
    type Error = Infallible;

    fn begin(&mut self, revision: &str) -> Result<(), Infallible> {
        self.revision = revision.to_owned();
        Ok(())
    }

    fn write(&mut self, batch: Batch) -> Result<(), Infallible> {
        match batch {
            Batch::RpslObjects(v) => add(self, v),
            Batch::Journal(v) => add(self, v),
            Batch::DatabaseStatus(v) => add(self, v),
            Batch::Roas(v) => add(self, v),
            Batch::Suspended(v) => add(self, v),
            Batch::ProtectedNames(v) => add(self, v),
            Batch::Settings(v) => add(self, v),
            Batch::AuthUsers(v) => add(self, v),
            Batch::AuthMntners(v) => add(self, v),
            Batch::AuthPermissions(v) => add(self, v),
            Batch::AuthApiTokens(v) => add(self, v),
            Batch::AuthWebauthn(v) => add(self, v),
            Batch::ChangeLog(v) => add(self, v),
            Batch::SerialGlobalLastValue(v) => self.serial_global = Some(v),
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Infallible> {
        self.finished = true;
        Ok(())
    }
}

#[test]
fn reader_matches_v4_export() {
    let (Ok(dsn), Ok(export)) = (
        std::env::var("IRRD_NG_TEST_V4_DSN"),
        std::env::var("IRRD_NG_TEST_V4_EXPORT"),
    ) else {
        eprintln!("IRRD_NG_TEST_V4_DSN / IRRD_NG_TEST_V4_EXPORT unset, skipping");
        return;
    };
    let export = PathBuf::from(export);
    let mut client = import_v4::connect(&dsn).expect("connect");
    let mut sink = Collect::default();
    // A small batch size, so multi-batch streaming is exercised too.
    let stats =
        import_v4::import(&mut client, &mut sink, &Options { batch_rows: 97 }).expect("import");
    assert!(sink.finished);
    assert_eq!(sink.revision, "e1e649b5f8bb");
    assert_eq!(stats.tables.len(), 13);
    assert_eq!(sink.serial_global, Some(stats.serial_global_last_value));

    for (table, n) in &stats.tables {
        let expected = std::fs::read(export.join(format!("{table}.jsonl"))).expect("export file");
        let mut rows = sink.tables.remove(table).unwrap_or_default();
        assert_eq!(rows.len() as u64, *n);
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        let got: Vec<u8> = rows.into_iter().flat_map(|(_, l)| l).collect();
        if got != expected {
            let g = String::from_utf8_lossy(&got);
            let e = String::from_utf8_lossy(&expected);
            let (gl, el) = g
                .lines()
                .zip(e.lines())
                .find(|(a, b)| a != b)
                .unwrap_or(("<length differs>", ""));
            panic!("{table} differs from v4's export\n  irrd-ng: {gl}\n  v4:      {el}");
        }
        eprintln!("{table}: {n} rows identical");
    }
}
