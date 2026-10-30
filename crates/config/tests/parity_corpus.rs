//! Differential test against IRRd v4's own verdicts on `irrd.yaml` files.
//!
//! `parity/corpus/config/expected.jsonl` holds, for every corpus file, the
//! error list v4 4.5.4 returned and the message it would exit with, as
//! recorded by the v4 oracle (`parity/oracle/run.sh config`). irrd-ng must
//! produce the same, except for the two reviewed divergences DIV-001 and
//! DIV-002 in `docs/divergences.md`, which must produce the fixed text.
//!
//! `parity/corpus/config/crash/expected.jsonl` holds the exception v4 raises
//! on files that crash it; irrd-ng must report the same exception.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use config::messages::{V4_NRTM4_SERVER_REQUIRES_KEEP_JOURNAL, V4_RPKI_NOTIFY_INVALID_NOT_SET};
use config::{ConfigError, Staging, check_source_with_fs, str_list_repr};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../parity/corpus/config")
}

/// A minimal reader for the oracle's JSON lines: an object with string
/// keys whose values are strings, null, or arrays of strings.
mod json {
    #[derive(Debug, PartialEq)]
    pub(crate) enum Value {
        Null,
        Str(String),
        List(Vec<String>),
    }

    pub(crate) fn parse_line(line: &str) -> Vec<(String, Value)> {
        let mut p = Parser {
            chars: line.chars().collect(),
            pos: 0,
        };
        p.object()
    }

    struct Parser {
        chars: Vec<char>,
        pos: usize,
    }

    impl Parser {
        fn ws(&mut self) {
            while self.chars.get(self.pos).is_some_and(|c| c.is_whitespace()) {
                self.pos += 1;
            }
        }

        fn eat(&mut self, c: char) {
            self.ws();
            assert_eq!(self.chars.get(self.pos), Some(&c), "at {}", self.pos);
            self.pos += 1;
        }

        fn peek(&mut self) -> char {
            self.ws();
            self.chars[self.pos]
        }

        fn string(&mut self) -> String {
            self.eat('"');
            let mut out = String::new();
            loop {
                let c = self.chars[self.pos];
                self.pos += 1;
                match c {
                    '"' => return out,
                    '\\' => {
                        let e = self.chars[self.pos];
                        self.pos += 1;
                        match e {
                            'n' => out.push('\n'),
                            't' => out.push('\t'),
                            'r' => out.push('\r'),
                            'b' => out.push('\u{8}'),
                            'f' => out.push('\u{c}'),
                            '/' => out.push('/'),
                            '\\' => out.push('\\'),
                            '"' => out.push('"'),
                            'u' => {
                                let mut code = self.hex4();
                                if (0xD800..0xDC00).contains(&code) {
                                    self.pos += 2;
                                    let low = self.hex4();
                                    code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                                }
                                out.push(char::from_u32(code).unwrap());
                            }
                            other => panic!("bad escape {other}"),
                        }
                    }
                    c => out.push(c),
                }
            }
        }

        fn hex4(&mut self) -> u32 {
            let s: String = self.chars[self.pos..self.pos + 4].iter().collect();
            self.pos += 4;
            u32::from_str_radix(&s, 16).unwrap()
        }

        fn value(&mut self) -> Value {
            match self.peek() {
                'n' => {
                    self.pos += 4;
                    Value::Null
                }
                '"' => Value::Str(self.string()),
                '[' => {
                    self.eat('[');
                    let mut items = Vec::new();
                    if self.peek() == ']' {
                        self.pos += 1;
                        return Value::List(items);
                    }
                    loop {
                        items.push(self.string());
                        if self.peek() == ',' {
                            self.pos += 1;
                        } else {
                            self.eat(']');
                            return Value::List(items);
                        }
                    }
                }
                other => panic!("unexpected {other}"),
            }
        }

        fn object(&mut self) -> Vec<(String, Value)> {
            self.eat('{');
            let mut out = Vec::new();
            loop {
                let k = self.string();
                self.eat(':');
                out.push((k, self.value()));
                if self.peek() == ',' {
                    self.pos += 1;
                } else {
                    self.eat('}');
                    return out;
                }
            }
        }
    }
}

struct Expected {
    file: String,
    errors: Option<Vec<String>>,
    other: Option<String>,
}

fn load_expected(path: &Path, other_key: &str) -> Vec<Expected> {
    let text = std::fs::read_to_string(path).unwrap();
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let mut row = Expected {
                file: String::new(),
                errors: None,
                other: None,
            };
            for (k, v) in json::parse_line(line) {
                match (k.as_str(), v) {
                    ("file", json::Value::Str(s)) => row.file = s,
                    ("errors", json::Value::List(l)) => row.errors = Some(l),
                    ("errors", json::Value::Null) => row.errors = None,
                    (k, json::Value::Str(s)) if k == other_key => row.other = Some(s),
                    (k, json::Value::Null) if k == other_key => row.other = None,
                    (k, v) => panic!("unexpected field {k}: {v:?}"),
                }
            }
            row
        })
        .collect()
}

/// Map v4's text for the two reviewed divergences to irrd-ng's.
fn apply_divergences(expected: &str, actual: &str) -> Option<String> {
    if expected == V4_RPKI_NOTIFY_INVALID_NOT_SET {
        return Some(
            V4_RPKI_NOTIFY_INVALID_NOT_SET.replace("true or false.DANGER", "true or false. DANGER"),
        );
    }
    if expected == V4_NRTM4_SERVER_REQUIRES_KEEP_JOURNAL {
        // v4 prints a literal "{name}"; irrd-ng names the source.
        let name = actual
            .strip_prefix("NRTMv4 server requires keep_journal to be set for source ")
            .and_then(|s| s.strip_suffix('.'))
            .filter(|n| !n.is_empty() && !n.contains('{'))
            .unwrap_or("<missing source name>");
        return Some(format!(
            "NRTMv4 server requires keep_journal to be set for source {name}."
        ));
    }
    None
}

/// Directories that exist in the v4 oracle's container but not necessarily
/// on the test host: the harness configuration's piddir.
const CONTAINER_ONLY_DIRS: &[&str] = &["/run/irrd"];

fn run(dir: &Path, file: &str) -> Result<Staging, config::PyException> {
    let display = format!("/input/{file}");
    let is_dir = |p: &str| CONTAINER_ONLY_DIRS.contains(&p) || Path::new(p).is_dir();
    check_source_with_fs(&display, std::fs::read(dir.join(file)), &is_dir)
}

#[test]
fn corpus_matches_v4() {
    let dir = corpus_dir();
    let expected = load_expected(&dir.join("expected.jsonl"), "startup_error");
    assert!(expected.len() > 150, "corpus is incomplete");
    let mut failures = Vec::new();
    let mut divergences_seen = 0;
    for case in &expected {
        let v4_errors = case.errors.clone().unwrap_or_default();
        // The oracle's startup message is v4's own repr() of its list, so
        // this also checks irrd-ng's Python repr against Python's.
        let v4_startup = (!v4_errors.is_empty())
            .then(|| config::messages::unable_to_start(&str_list_repr(&v4_errors)));
        if v4_startup != case.other {
            failures.push(format!(
                "{}: repr mismatch\n  python: {:?}\n  ours:   {:?}",
                case.file, case.other, v4_startup
            ));
            continue;
        }

        let actual = match run(&dir, &case.file) {
            Ok(staging) => staging.errors().to_vec(),
            Err(e) => {
                failures.push(format!("{}: unexpected exception {e}", case.file));
                continue;
            }
        };
        let mut wanted = v4_errors.clone();
        for (i, w) in wanted.iter_mut().enumerate() {
            if let Some(fixed) = apply_divergences(w, actual.get(i).map_or("", String::as_str)) {
                *w = fixed;
                divergences_seen += 1;
            }
        }
        if actual != wanted {
            let mut msg = format!("{}: errors differ", case.file);
            for i in 0..actual.len().max(wanted.len()) {
                let (a, w) = (actual.get(i), wanted.get(i));
                if a != w {
                    msg.push_str(&format!("\n  [{i}] v4:   {w:?}\n  [{i}] ours: {a:?}"));
                }
            }
            failures.push(msg);
            continue;
        }
        let startup = (!actual.is_empty()).then(|| {
            ConfigError::Invalid {
                errors: actual.clone(),
            }
            .to_string()
        });
        let wanted_startup = (!wanted.is_empty())
            .then(|| config::messages::unable_to_start(&str_list_repr(&wanted)));
        if startup != wanted_startup {
            failures.push(format!("{}: startup message differs", case.file));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} corpus files differ from v4:\n{}",
        failures.len(),
        expected.len(),
        failures.join("\n")
    );
    assert!(divergences_seen >= 2, "DIV-001/DIV-002 not exercised");
}

#[test]
fn crash_corpus_matches_v4() {
    let dir = corpus_dir().join("crash");
    let expected = load_expected(&dir.join("expected.jsonl"), "exception");
    assert!(!expected.is_empty());
    let mut failures = Vec::new();
    for case in &expected {
        let Some(v4_exception) = &case.other else {
            failures.push(format!(
                "{}: v4 did not crash on a crash corpus file",
                case.file
            ));
            continue;
        };
        match run(&dir, &case.file) {
            Ok(staging) => failures.push(format!(
                "{}: v4 raises {v4_exception}, irrd-ng returned {:?}",
                case.file,
                staging.errors()
            )),
            Err(e) if e.to_string() == *v4_exception => {}
            Err(e) => failures.push(format!(
                "{}: exception differs\n  v4:   {v4_exception}\n  ours: {e}",
                case.file
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} crash corpus files differ from v4:\n{}",
        failures.len(),
        expected.len(),
        failures.join("\n")
    );
}

/// `parity/corpus/config/yaml/` holds fuzzed YAML documents, one per
/// distinct PyYAML outcome, with what PyYAML's `safe_load` made of each.
#[test]
fn yaml_corpus_matches_pyyaml() {
    let dir = corpus_dir().join("yaml");
    let expected = load_expected(&dir.join("expected.jsonl"), "result");
    assert!(!expected.is_empty());
    let mut failures = Vec::new();
    for case in &expected {
        let bytes = std::fs::read(dir.join(&case.file)).unwrap();
        let ours = config::__private::yaml_load_repr(&format!("/input/{}", case.file), &bytes);
        if Some(&ours) != case.other.as_ref() {
            failures.push(format!(
                "{}\n  pyyaml: {:?}\n  ours:   {ours:?}",
                case.file, case.other
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} YAML files differ from PyYAML:\n{}",
        failures.len(),
        expected.len(),
        failures.join("\n")
    );
}
