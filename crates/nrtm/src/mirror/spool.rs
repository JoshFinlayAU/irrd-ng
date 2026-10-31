//! Bounded-memory plumbing for large imports.
//!
//! v4 streams a full import or an NRTMv4 snapshot through one database
//! transaction. irrd-ng parses outside the write transaction instead, so
//! the single LMDB writer is held only for the writes; to keep memory
//! bounded for sources of millions of objects, the parsed rows go to a
//! temporary spool file and the write transaction reads them back. The
//! spool can be replayed, so a write retried after the map grew sees the
//! same rows.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};

use serde::{Deserialize, Serialize};
use store::NewRpslObject;

use crate::file_import::ImportAction;
use crate::mirror::pyerr::{PyErr, os_error};

/// One spooled write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpoolItem {
    /// `upsert_rpsl_object(obj, origin=mirror)`
    Upsert(NewRpslObject),
    /// `record_mirror_error(source, error)`
    MirrorError(String),
}

/// A spool of parsed rows on disk.
#[derive(Debug)]
pub struct Spool {
    writer: Option<BufWriter<File>>,
    file: File,
    _path: tempfile::TempPath,
    /// (object class, primary key, offset, length) of every upsert, for key-order
    /// replay.
    index: Vec<(String, String, u64, u64)>,
    offset: u64,
    /// Rows spooled.
    pub items: u64,
    /// Bytes of object text spooled, for sizing the map.
    pub text_bytes: usize,
}

fn encode_err(e: postcard::Error) -> PyErr {
    PyErr::Other(e.to_string())
}

impl Spool {
    /// A new, empty spool in the temporary directory.
    pub fn new() -> Result<Spool, PyErr> {
        let tmp = tempfile::NamedTempFile::new().map_err(|e| os_error(&e, None))?;
        let (file, path) = tmp.into_parts();
        let writer = file.try_clone().map_err(|e| os_error(&e, None))?;
        Ok(Spool {
            writer: Some(BufWriter::with_capacity(1 << 20, writer)),
            file,
            _path: path,
            index: Vec::new(),
            offset: 0,
            items: 0,
            text_bytes: 0,
        })
    }

    /// Append one item.
    pub fn push(&mut self, item: &SpoolItem) -> Result<(), PyErr> {
        let bytes = postcard::to_stdvec(item).map_err(encode_err)?;
        if let SpoolItem::Upsert(o) = item {
            self.index.push((
                o.object_class.clone(),
                o.rpsl_pk.clone(),
                self.offset,
                4 + bytes.len() as u64,
            ));
            self.text_bytes += o.object_text.len();
        }
        let w = self
            .writer
            .as_mut()
            .ok_or_else(|| PyErr::Other("spool closed".into()))?;
        let len = u32::try_from(bytes.len()).map_err(|e| PyErr::Other(e.to_string()))?;
        w.write_all(&len.to_le_bytes())
            .and_then(|_| w.write_all(&bytes))
            .map_err(|e| os_error(&e, None))?;
        self.offset += 4 + bytes.len() as u64;
        self.items += 1;
        Ok(())
    }

    /// Append the result of parsing.
    pub fn push_action(&mut self, a: ImportAction) -> Result<(), PyErr> {
        match a {
            ImportAction::Upsert(o) => self.push(&SpoolItem::Upsert(o.object)),
            ImportAction::MirrorError(e) => self.push(&SpoolItem::MirrorError(e)),
        }
    }

    /// Finish writing.
    pub fn close(&mut self) -> Result<(), PyErr> {
        if let Some(mut w) = self.writer.take() {
            w.flush().map_err(|e| os_error(&e, None))?;
        }
        Ok(())
    }

    /// Sort the upsert index by (object class, primary key), keeping file
    /// order between duplicates, so a replay in key order writes the last
    /// one last.
    pub fn sort_by_key(&mut self) {
        self.index.sort_by(|a, b| {
            (a.0.as_bytes(), a.1.as_bytes()).cmp(&(b.0.as_bytes(), b.1.as_bytes()))
        });
    }

    fn reader(&self) -> std::io::Result<BufReader<File>> {
        let mut f = self.file.try_clone()?;
        f.seek(SeekFrom::Start(0))?;
        Ok(BufReader::with_capacity(1 << 20, f))
    }

    fn read_one(r: &mut impl Read) -> std::io::Result<Option<SpoolItem>> {
        let mut len = [0u8; 4];
        match r.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let mut buf = vec![0u8; u32::from_le_bytes(len) as usize];
        r.read_exact(&mut buf)?;
        postcard::from_bytes(&buf)
            .map(Some)
            .map_err(std::io::Error::other)
    }

    /// Replay every item in the order pushed.
    pub fn for_each(&self, f: &mut dyn FnMut(SpoolItem) -> store::Result<()>) -> store::Result<()> {
        let io = |e: std::io::Error| store::StoreError::Io("<spool>".into(), e);
        let mut r = self.reader().map_err(io)?;
        while let Some(item) = Self::read_one(&mut r).map_err(io)? {
            f(item)?;
        }
        Ok(())
    }

    /// Replay: mirror errors in the order pushed, then upserts in the
    /// order of the index (see [`Spool::sort_by_key`]).
    pub fn for_each_sorted(
        &self,
        f: &mut dyn FnMut(SpoolItem) -> store::Result<()>,
    ) -> store::Result<()> {
        let io = |e: std::io::Error| store::StoreError::Io("<spool>".into(), e);
        self.for_each(&mut |item| match item {
            SpoolItem::MirrorError(_) => f(item),
            SpoolItem::Upsert(_) => Ok(()),
        })?;
        let mut r = self.reader().map_err(io)?;
        let mut pos = 0u64;
        for (_, _, offset, len) in &self.index {
            if *offset != pos {
                r.seek(SeekFrom::Start(*offset)).map_err(io)?;
            }
            let item = Self::read_one(&mut r)
                .map_err(io)?
                .ok_or(store::StoreError::Corrupt("spool"))?;
            pos = *offset + *len;
            f(item)?;
        }
        Ok(())
    }
}

/// Reads an RPSL file a block at a time and splits it into paragraphs as
/// v4 does for a file (`split_paragraphs_rpsl(open(f, encoding="utf-8",
/// errors="backslashreplace"))`): universal newlines, `#` and `%` lines
/// dropped, paragraphs ending at an empty line.
#[derive(Debug)]
pub struct ParagraphReader<R: Read> {
    inner: BufReader<R>,
    carry: Vec<u8>,
    current: String,
    eof: bool,
    pending: std::collections::VecDeque<String>,
}

const BLOCK: usize = 8 << 20;

impl<R: Read> ParagraphReader<R> {
    /// Read from `inner`.
    pub fn new(inner: R) -> Self {
        ParagraphReader {
            inner: BufReader::with_capacity(BLOCK, inner),
            carry: Vec::new(),
            current: String::new(),
            eof: false,
            pending: std::collections::VecDeque::new(),
        }
    }

    fn line(&mut self, line: &str) {
        let line = line.trim_matches(['\r', '\n']);
        if line.starts_with('%') || line.starts_with('#') {
            return;
        }
        if line.is_empty() {
            if !self.current.is_empty() {
                self.pending.push_back(std::mem::take(&mut self.current));
            }
        } else {
            self.current.push_str(line);
            self.current.push('\n');
        }
    }

    fn lines_of(&mut self, bytes: &[u8]) {
        let text = rpsl::decode_rpsl_file(bytes);
        for l in text.split_inclusive('\n') {
            self.line(l);
        }
    }

    /// Up to `max` more paragraphs; empty at the end.
    pub fn next_chunk(&mut self, max: usize) -> std::io::Result<Vec<String>> {
        while self.pending.len() < max && !self.eof {
            let buf = self.inner.fill_buf()?;
            if buf.is_empty() {
                self.eof = true;
                let rest = std::mem::take(&mut self.carry);
                self.lines_of(&rest);
                if !rpsl::text::py_strip(&self.current).is_empty() {
                    self.pending.push_back(std::mem::take(&mut self.current));
                }
                break;
            }
            let n = buf.len();
            self.carry.extend_from_slice(buf);
            self.inner.consume(n);
            // Decode whole lines only: a '\n' never splits a UTF-8
            // sequence or a "\r\n" pair.
            if let Some(cut) = self.carry.iter().rposition(|b| *b == b'\n') {
                let rest = self.carry.split_off(cut + 1);
                let head = std::mem::replace(&mut self.carry, rest);
                self.lines_of(&head);
            }
        }
        let n = max.min(self.pending.len());
        Ok(self.pending.drain(..n).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paragraphs_match_whole_file_splitting() {
        let text = b"\n\n%comment\nperson: A\r\n# c\naddress: x\n\n\nroute: 192.0.2.0/24\r\norigin: AS1\rsource: T\n \nmore: x\n\xff\n\nlast: y";
        let whole = rpsl::split_rpsl_file(text);
        for chunk in [1, 2, 1000] {
            let mut r = ParagraphReader::new(&text[..]);
            let mut got = Vec::new();
            loop {
                let c = r.next_chunk(chunk).expect("read");
                if c.is_empty() {
                    break;
                }
                got.extend(c);
            }
            assert_eq!(got, whole);
        }
    }

    #[test]
    fn spool_replays_in_both_orders() {
        let mut s = Spool::new().expect("spool");
        let obj = |pk: &str, text: &str| NewRpslObject {
            rpsl_pk: pk.into(),
            source: "TEST".into(),
            object_class: "mntner".into(),
            parsed_data: store::Json("{}".into()),
            object_text: text.into(),
            ip_first: None,
            ip_last: None,
            prefix: None,
            prefix_length: None,
            asn_first: None,
            asn_last: None,
            rpki_status: store::RpkiStatus::NotFound,
            scopefilter_status: store::ScopeFilterStatus::InScope,
            route_preference_status: store::RoutePreferenceStatus::Visible,
        };
        s.push(&SpoolItem::Upsert(obj("B", "1"))).expect("push");
        s.push(&SpoolItem::MirrorError("e".into())).expect("push");
        s.push(&SpoolItem::Upsert(obj("A", "2"))).expect("push");
        s.push(&SpoolItem::Upsert(obj("B", "3"))).expect("push");
        s.close().expect("close");
        let mut seen = Vec::new();
        s.for_each(&mut |i| {
            seen.push(match i {
                SpoolItem::Upsert(o) => format!("{}{}", o.rpsl_pk, o.object_text),
                SpoolItem::MirrorError(e) => e,
            });
            Ok(())
        })
        .expect("replay");
        assert_eq!(seen, ["B1", "e", "A2", "B3"]);
        s.sort_by_key();
        for _ in 0..2 {
            let mut seen = Vec::new();
            s.for_each_sorted(&mut |i| {
                seen.push(match i {
                    SpoolItem::Upsert(o) => format!("{}{}", o.rpsl_pk, o.object_text),
                    SpoolItem::MirrorError(e) => e,
                });
                Ok(())
            })
            .expect("replay");
            assert_eq!(seen, ["e", "A2", "B1", "B3"]);
        }
    }
}
