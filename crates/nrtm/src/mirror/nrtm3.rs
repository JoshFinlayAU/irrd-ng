//! `NRTMStreamParser` (`irrd/mirroring/parsers.py`): split an NRTMv3 (or
//! v1) response into ADD/DEL operations with their serials.
//!
//! Pure: v4 also records each stream error as a mirror error, but the
//! runner then rolls the transaction back, so only the log line and the
//! exception remain. Those are what this returns.

use crate::messages;
use crate::mirror::pyerr::PyErr;

/// v4's logger name.
pub const LOG_TARGET: &str = "irrd.mirroring.parsers";

/// `DatabaseOperation` for NRTM: its value is the keyword.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// `add_or_update` (`ADD`)
    Add,
    /// `delete` (`DEL`)
    Del,
}

impl Operation {
    /// `operation.value`
    pub fn value(self) -> &'static str {
        match self {
            Operation::Add => "ADD",
            Operation::Del => "DEL",
        }
    }
}

/// One operation from the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOperation {
    /// ADD or DEL.
    pub operation: Operation,
    /// Its serial.
    pub serial: i64,
    /// The object paragraph, as split.
    pub object_text: String,
}

/// A parsed stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NrtmStream {
    /// From the START line, or -1.
    pub first_serial: i64,
    /// From the START line, or -1. Recorded as `serial_newest_mirror`
    /// when above 0.
    pub last_serial: i64,
    /// The source on the START line, upper-cased.
    pub nrtm_source: Option<String>,
    /// The operations, in order.
    pub operations: Vec<StreamOperation>,
}

/// `nrtm_start_line_re.match(paragraph)`: `(version, source, first, last)`.
///
/// `^% *START *Version: *(\d+) +([\w-]+) +(\d+)-(\d+)( FILTERED)?\n$` with
/// `re.MULTILINE`, so the paragraph must be that one line.
fn match_start_line(p: &str) -> Option<(String, String, String, String)> {
    let mut s = p.strip_prefix('%')?;
    s = s.trim_start_matches(' ');
    s = s.strip_prefix("START")?;
    s = s.trim_start_matches(' ');
    s = s.strip_prefix("Version:")?;
    s = s.trim_start_matches(' ');
    let digits = |s: &str| s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let n = digits(s);
    if n == 0 {
        return None;
    }
    let version = s[..n].to_owned();
    s = &s[n..];
    let sp = s.len() - s.trim_start_matches(' ').len();
    if sp == 0 {
        return None;
    }
    s = &s[sp..];
    let n = s
        .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-'))
        .unwrap_or(s.len());
    if n == 0 {
        return None;
    }
    let source = s[..n].to_owned();
    s = &s[n..];
    let sp = s.len() - s.trim_start_matches(' ').len();
    if sp == 0 {
        return None;
    }
    s = &s[sp..];
    let n = digits(s);
    if n == 0 {
        return None;
    }
    let first = s[..n].to_owned();
    s = s[n..].strip_prefix('-')?;
    let n = digits(s);
    if n == 0 {
        return None;
    }
    let last = s[..n].to_owned();
    s = &s[n..];
    s = s.strip_prefix(" FILTERED").unwrap_or(s);
    // "\n$" in MULTILINE mode: the newline, then the end or another
    // newline.
    let rest = s.strip_prefix('\n')?;
    if !(rest.is_empty() || rest.starts_with('\n')) {
        return None;
    }
    Some((version, source, first, last))
}

fn stream_error(msg: String) -> PyErr {
    tracing::error!(target: LOG_TARGET, "{msg}");
    PyErr::Value(msg)
}

fn to_i64(s: &str) -> Result<i64, PyErr> {
    crate::mirror::pyerr::py_int(s)
}

/// `NRTMStreamParser(source, nrtm_data)`.
pub fn parse_nrtm_stream(source: &str, data: &str) -> Result<NrtmStream, PyErr> {
    let paragraphs = rpsl::split_paragraphs_rpsl(data, false);
    let mut it = paragraphs.into_iter();
    let mut out = NrtmStream {
        first_serial: -1,
        last_serial: -1,
        nrtm_source: None,
        operations: Vec::new(),
    };
    let mut version = String::new();
    let mut current_op_serial: i64 = -1;
    let mut last_comment_seen = String::new();

    while let Some(paragraph) = it.next() {
        if let Some((v, src, first, last)) = match_start_line(&paragraph) {
            if out.nrtm_source.is_some() {
                return Err(stream_error(messages::nrtm_second_start(
                    source,
                    out.first_serial,
                    out.last_serial,
                    &paragraph,
                )));
            }
            version = v;
            let nrtm_source = src.to_uppercase();
            out.first_serial = to_i64(&first)?;
            out.last_serial = to_i64(&last)?;
            out.nrtm_source = Some(nrtm_source.clone());
            if source != nrtm_source {
                return Err(stream_error(messages::nrtm_invalid_source(
                    source,
                    &nrtm_source,
                    &paragraph,
                )));
            }
            if version != "1" && version != "3" {
                return Err(stream_error(messages::nrtm_invalid_version(
                    &version, &paragraph,
                )));
            }
            tracing::debug!(target: LOG_TARGET, "{}", messages::nrtm_valid_start(source, out.first_serial, out.last_serial));
            continue;
        }
        if paragraph.starts_with('%') || paragraph.starts_with('#') {
            last_comment_seen = paragraph;
        } else if paragraph.starts_with("ADD") || paragraph.starts_with("DEL") {
            if out.nrtm_source.is_none() {
                return Err(stream_error(messages::nrtm_operation_before_start(
                    &paragraph,
                )));
            }
            if current_op_serial == -1 {
                current_op_serial = out.first_serial;
            } else {
                current_op_serial += 1;
            }
            let operation_str: String;
            if paragraph.contains(' ') {
                let parts: Vec<&str> = paragraph.split(' ').collect();
                if parts.len() != 2 {
                    let msg = if parts.len() > 2 {
                        "too many values to unpack (expected 2)".to_owned()
                    } else {
                        "not enough values to unpack (expected 2, got 1)".to_owned()
                    };
                    return Err(PyErr::Value(msg));
                }
                operation_str = parts[0].to_owned();
                let line_serial = to_i64(parts[1])?;
                // Gaps are allowed, but the serial can never be lower,
                // which would mean operations in the wrong order.
                if line_serial < current_op_serial {
                    return Err(stream_error(messages::nrtm_invalid_serial(
                        source,
                        line_serial,
                        current_op_serial,
                    )));
                }
                current_op_serial = line_serial;
            } else {
                operation_str = rpsl::text::py_strip(&paragraph).to_owned();
            }
            let operation = match operation_str.as_str() {
                "ADD" => Operation::Add,
                "DEL" => Operation::Del,
                other => {
                    return Err(PyErr::Value(format!(
                        "{} is not a valid DatabaseOperation",
                        config::str_repr(other)
                    )));
                }
            };
            // next(paragraphs): StopIteration, whose str() is empty.
            let object_text = it.next().ok_or_else(|| PyErr::Other(String::new()))?;
            out.operations.push(StreamOperation {
                operation,
                serial: current_op_serial,
                object_text,
            });
        }
    }

    if out.nrtm_source.is_some() {
        let last = rpsl::text::py_strip(&last_comment_seen.to_uppercase()).to_owned();
        if last != format!("%END {source}") {
            return Err(stream_error(messages::nrtm_no_end(source, &last)));
        }
    }
    if current_op_serial > out.last_serial && version != "3" {
        return Err(stream_error(messages::nrtm_too_many_operations(
            source,
            out.last_serial,
            current_op_serial,
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    //! v4's `TestNRTMStreamParser` and its samples (`nrtm_samples.py`).

    use super::*;

    const SAMPLE_NRTM_V3: &str = "\n% NRTM v3 contains serials per object.\n\n% Another comment\n\n%START Version: 3 TEST 11012700-11012701\n\nADD 11012700\n\nperson: NRTM test\naddress: NowhereLand\nsource: TEST\n\nDEL 11012701\n\ninetnum: 192.0.2.0 - 192.0.2.255\nsource: TEST\n\n%END TEST\n";
    const SAMPLE_NRTM_V1: &str = "%START Version: 1 TEST 11012700-11012701\n\nADD\n\nperson: NRTM test\naddress: NowhereLand\nsource: TEST\n\nDEL\n\ninetnum: 192.0.2.0 - 192.0.2.255\nsource: TEST\n\n%END TEST\n";
    const SAMPLE_NRTM_V1_TOO_MANY_ITEMS: &str = "\n% The serial range is one item, but there are two items in here.\n\n%START Version: 1 TEST 11012700-11012700 FILTERED\n\nADD\n\nperson: NRTM test\naddress: NowhereLand\nsource: TEST\n\nDEL\n\ninetnum: 192.0.2.0 - 192.0.2.255\nsource: TEST\n\n%END TEST\n";
    const SAMPLE_NRTM_INVALID_VERSION: &str = "%START Version: 99 TEST 11012700-11012700";
    const SAMPLE_NRTM_V3_SERIAL_GAP: &str = "\n# NRTM v3 serials are allowed to have gaps per https://github.com/irrdnet/irrd/issues/85\n\n%START Version: 3 TEST 11012699-11012703\n\nADD 11012700\n\nperson: NRTM test\naddress: NowhereLand\nsource: TEST\n\n\nDEL 11012701\n\ninetnum: 192.0.2.0 - 192.0.2.255\nsource: TEST\n\n%END TEST\n";
    const SAMPLE_NRTM_V3_SERIAL_OUT_OF_ORDER: &str = "\n# NRTM v3 serials can have gaps, but must always increase.\n\n%START Version: 3 TEST 11012699-11012703\n\nADD 11012701\n\nperson: NRTM test\naddress: NowhereLand\nsource: TEST\n\nDEL 11012701\n\ninetnum: 192.0.2.0 - 192.0.2.255\nsource: TEST\n\n%END TEST\n";
    const SAMPLE_NRTM_V3_INVALID_MULTIPLE_START_LINES: &str = "\n%START Version: 3 TEST 11012700-11012700\n\n%START Version: 3 ARIN 11012700-11012700\n\nADD 11012701\n\nperson: NRTM test\naddress: NowhereLand\nsource: TEST\n\n%END TEST\n";
    const SAMPLE_NRTM_INVALID_NO_START_LINE: &str = "\nADD 11012701\n\nperson: NRTM test\naddress: NowhereLand\nsource: TEST\n\nDEL 11012700\n\ninetnum: 192.0.2.0 - 192.0.2.255\nsource: TEST\n\n%END TEST\n";
    const SAMPLE_NRTM_V3_NO_END: &str = "%START Version: 3 TEST 11012700-11012701";

    fn assert_valid(p: &NrtmStream) {
        assert_eq!(p.operations[0].operation, Operation::Add);
        assert_eq!(p.operations[0].serial, 11012700);
        assert_eq!(
            p.operations[0].object_text,
            "person: NRTM test\naddress: NowhereLand\nsource: TEST\n"
        );
        assert_eq!(p.operations[1].operation, Operation::Del);
        assert_eq!(p.operations[1].serial, 11012701);
        assert_eq!(
            p.operations[1].object_text,
            "inetnum: 192.0.2.0 - 192.0.2.255\nsource: TEST\n"
        );
    }

    #[test]
    fn v3_valid() {
        let p = parse_nrtm_stream("TEST", SAMPLE_NRTM_V3).expect("valid");
        assert_valid(&p);
        assert_eq!(p.last_serial, 11012701);
    }

    #[test]
    fn v1_valid() {
        let p = parse_nrtm_stream("TEST", SAMPLE_NRTM_V1).expect("valid");
        assert_valid(&p);
        assert_eq!(p.last_serial, 11012701);
    }

    #[test]
    fn v3_serial_gap() {
        let p = parse_nrtm_stream("TEST", SAMPLE_NRTM_V3_SERIAL_GAP).expect("valid");
        assert_valid(&p);
        assert_eq!(p.last_serial, 11012703);
    }

    fn err(source: &str, data: &str) -> String {
        match parse_nrtm_stream(source, data) {
            Err(PyErr::Value(m)) => m,
            other => panic!("expected a ValueError, got {other:?}"),
        }
    }

    #[test]
    fn v3_serial_out_of_order() {
        assert!(err("TEST", SAMPLE_NRTM_V3_SERIAL_OUT_OF_ORDER).contains("expected at least"));
    }

    #[test]
    fn unexpected_source() {
        assert!(
            err("BADSOURCE", SAMPLE_NRTM_V3)
                .contains("Invalid NRTM source in START line: expected BADSOURCE but found TEST ")
        );
    }

    #[test]
    fn v1_too_many_items() {
        assert!(
            err("TEST", SAMPLE_NRTM_V1_TOO_MANY_ITEMS)
                .contains("expected operations up to and including")
        );
    }

    #[test]
    fn invalid_version() {
        assert!(
            err("TEST", SAMPLE_NRTM_INVALID_VERSION)
                .contains("Invalid NRTM version 99 in START line")
        );
    }

    #[test]
    fn multiple_start_lines() {
        assert!(
            err("TEST", SAMPLE_NRTM_V3_INVALID_MULTIPLE_START_LINES)
                .contains("Encountered second START line")
        );
    }

    #[test]
    fn no_start_line() {
        assert!(
            err("TEST", SAMPLE_NRTM_INVALID_NO_START_LINE)
                .contains("Encountered operation before valid NRTM START line")
        );
    }

    #[test]
    fn no_end() {
        let m = err("TEST", SAMPLE_NRTM_V3_NO_END);
        assert!(m.contains("last comment paragraph expected to be"));
        assert_eq!(
            m,
            "NRTM stream error for TEST: last comment paragraph expected to be \"%END TEST\", but is actually \"\" - could be caused by TCP disconnection during NRTM query or mirror server returning an error or an otherwise incomplete or invalid response"
        );
    }

    #[test]
    fn error_responses_are_not_streams() {
        // A server error without a START line: no operations, no error.
        let p = parse_nrtm_stream("TEST", "%ERROR:401: invalid range\n").expect("no stream");
        assert!(p.operations.is_empty());
        assert_eq!(p.last_serial, -1);
    }

    #[test]
    fn malformed_operation_lines() {
        let base = "%START Version: 3 TEST 1-2\n\n";
        assert_eq!(
            parse_nrtm_stream("TEST", &format!("{base}ADD 1 2\n\nperson: x\n")),
            Err(PyErr::Value(
                "too many values to unpack (expected 2)".into()
            ))
        );
        assert_eq!(
            parse_nrtm_stream("TEST", &format!("{base}ADDX 1\n\nperson: x\n")),
            Err(PyErr::Value(
                "'ADDX' is not a valid DatabaseOperation".into()
            ))
        );
        assert_eq!(
            parse_nrtm_stream("TEST", &format!("{base}ADD x\n\nperson: x\n")),
            Err(PyErr::Value(
                "invalid literal for int() with base 10: 'x\\n'".into()
            ))
        );
        assert_eq!(
            parse_nrtm_stream("TEST", &format!("{base}ADD 1\n")),
            Err(PyErr::Other(String::new()))
        );
    }
}
