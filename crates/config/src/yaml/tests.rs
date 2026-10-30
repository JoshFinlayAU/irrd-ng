//! Tests for the PyYAML port. The differential corpora under
//! `parity/corpus/config/` cover far more; these pin the YAML 1.1 typing
//! rules a Rust YAML library would get wrong.

use super::{LoadError, safe_load};

fn load(text: &str) -> String {
    match safe_load("t.yaml", text) {
        Ok(v) => v.py_repr(),
        Err(LoadError::Yaml(e)) => format!("ERR {e}"),
        Err(LoadError::Crash(e)) => format!("CRASH {e}"),
    }
}

#[test]
fn yaml_11_scalars() {
    // Expected values are PyYAML 6.0.3's safe_load results.
    let cases: &[(&str, &str)] = &[
        ("a: yes", "{'a': True}"),
        ("a: Off", "{'a': False}"),
        ("a: 'yes'", "{'a': 'yes'}"),
        ("a: y", "{'a': 'y'}"),
        ("a: 010", "{'a': 8}"),
        ("a: 0o10", "{'a': '0o10'}"),
        ("a: 0x1F", "{'a': 31}"),
        ("a: 0b101", "{'a': 5}"),
        ("a: 1_000", "{'a': 1000}"),
        ("a: 1:30", "{'a': 90}"),
        ("a: 1e5", "{'a': '1e5'}"),
        ("a: 1.0e+5", "{'a': 100000.0}"),
        ("a: .inf", "{'a': inf}"),
        ("a: ~", "{'a': None}"),
        ("a:", "{'a': None}"),
        ("a: 2020-01-02", "{'a': datetime.date(2020, 1, 2)}"),
        (
            "a: =",
            "ERR could not determine a constructor for the tag 'tag:yaml.org,2002:value'\n  in \"t.yaml\", line 1, column 4",
        ),
        ("a: 1\na: 2", "{'a': 2}"),
        ("{1: a, True: b}", "{1: 'b'}"),
    ];
    for (input, expected) in cases {
        assert_eq!(&load(input), expected, "{input:?}");
    }
}

#[test]
fn errors_name_the_file() {
    assert_eq!(
        load("a:\n\tb: 1\n"),
        "ERR while scanning for the next token\nfound character '\\t' that cannot start any token\n  in \"t.yaml\", line 2, column 1"
    );
}

#[test]
fn bad_characters_are_found_when_their_chunk_is_read() {
    // A scanner error in the first 8192 characters wins over a control
    // character further on, because PyYAML has not read that far yet.
    let mut text = "a: \"\\q\"\n".to_owned();
    text.push_str(&"# padding\n".repeat(1000));
    text.push('\x01');
    assert!(load(&text).starts_with("ERR while scanning a double-quoted scalar"));
    let mut text = "a: 1\n".to_owned();
    text.push('\x01');
    assert_eq!(
        load(&text),
        "ERR unacceptable character #x0001: special characters are not allowed\n  in \"t.yaml\", position 5"
    );
}
