//! `jsonseq_decode` (`irrd/mirroring/nrtm4/jsonseq.py`): RFC 7464 JSON text
//! sequences, read a block at a time.

use std::io::Read;

use config::Value;

use crate::mirror::nrtm4::json;

const RS: u8 = 0x1e;
const CHUNK_SIZE: usize = 1024 * 100;

/// Decodes one record at a time from a stream.
#[derive(Debug)]
pub struct JsonSeqReader<R: Read> {
    inner: R,
    buffer: Vec<u8>,
    ready: std::collections::VecDeque<Vec<u8>>,
    done: bool,
}

impl<R: Read> JsonSeqReader<R> {
    /// Read from `inner`.
    pub fn new(inner: R) -> Self {
        JsonSeqReader {
            inner,
            buffer: Vec::new(),
            ready: std::collections::VecDeque::new(),
            done: false,
        }
    }

    fn split_buffer(&mut self) {
        while let Some(pos) = self.buffer.iter().position(|b| *b == RS) {
            let seq: Vec<u8> = self.buffer.drain(..=pos).take(pos).collect();
            if !seq.is_empty() {
                self.ready.push_back(seq);
            }
        }
    }

    /// The next decoded record. Errors are an I/O error (`Err(Err)`) or
    /// the JSON parser's message (`Err(Ok)`).
    pub fn next_item(&mut self) -> Option<Result<Value, Result<String, std::io::Error>>> {
        loop {
            if let Some(seq) = self.ready.pop_front() {
                return Some(json::loads(&seq).map_err(Ok));
            }
            if self.done {
                return None;
            }
            let mut chunk = vec![0u8; CHUNK_SIZE];
            match self.inner.read(&mut chunk) {
                Err(e) => return Some(Err(Err(e))),
                Ok(0) => {
                    self.done = true;
                    self.split_buffer();
                    let rest = std::mem::take(&mut self.buffer);
                    if !rest.is_empty() {
                        self.ready.push_back(rest);
                    }
                }
                Ok(n) => {
                    self.buffer.extend_from_slice(&chunk[..n]);
                    self.split_buffer();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // v4's test_jsonseq.py round trip, plus empty records and a final
    // record without a separator.
    #[test]
    fn decodes_sequences() {
        let data = b"\x1e{\"a\": 1}\n\x1e\x1e[2]\n\x1e\"x\"";
        let mut r = JsonSeqReader::new(&data[..]);
        let mut got = Vec::new();
        while let Some(item) = r.next_item() {
            got.push(item.expect("json").py_repr());
        }
        assert_eq!(got, ["{'a': 1}", "[2]", "'x'"]);
        let mut r = JsonSeqReader::new(&b"\x1e{bad\n"[..]);
        assert!(matches!(r.next_item(), Some(Err(Ok(_)))));
    }
}
