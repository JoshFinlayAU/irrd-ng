//! `yaml/reader.py` for a text-mode file stream.
//!
//! PyYAML pulls the file in 4096-character reads and checks each batch for
//! characters YAML forbids only when it loads it, so a scanner error early in
//! a large file wins over a bad character further down. The read and check
//! sequence here follows `determine_encoding`, `update` and `update_raw`
//! exactly so that ordering is preserved.

use super::Mark;

const READ_SIZE: usize = 4096;

pub(crate) struct Reader {
    /// The whole stream, already decoded and newline-translated.
    text: Vec<char>,
    /// How much of `text` the simulated `stream.read()` calls have returned.
    stream_pointer: usize,
    /// `raw_buffer`: characters read but not yet moved into `buffer`.
    /// `None` once the end of the stream has been reached and appended.
    raw: Option<Vec<char>>,
    eof: bool,
    /// `buffer`, never trimmed, so `index` doubles as the pointer.
    buffer: Vec<char>,
    pub(crate) index: usize,
    pub(crate) line: usize,
    pub(crate) column: usize,
    /// The first `ReaderError`, as (position, character).
    error: Option<(usize, u32)>,
}

fn is_non_printable(c: char) -> bool {
    !matches!(c,
        '\x09' | '\x0A' | '\x0D' | '\x20'..='\x7E' | '\u{85}'
        | '\u{A0}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

impl Reader {
    pub(crate) fn new(text: &str) -> Self {
        let mut reader = Reader {
            text: text.chars().collect(),
            stream_pointer: 0,
            raw: None,
            eof: false,
            buffer: Vec::new(),
            index: 0,
            line: 0,
            column: 0,
            error: None,
        };
        // determine_encoding()
        while !reader.eof && reader.raw.as_ref().is_none_or(|r| r.len() < 2) {
            reader.update_raw();
        }
        reader.update(1);
        reader
    }

    pub(crate) fn error(&self) -> Option<(usize, u32)> {
        self.error
    }

    fn update_raw(&mut self) {
        let end = (self.stream_pointer + READ_SIZE).min(self.text.len());
        let data = &self.text[self.stream_pointer..end];
        let raw = self.raw.get_or_insert_with(Vec::new);
        raw.extend_from_slice(data);
        if data.is_empty() {
            self.eof = true;
        }
        self.stream_pointer = end;
    }

    fn update(&mut self, length: usize) {
        if self.error.is_some() || self.raw.is_none() {
            return;
        }
        while self.buffer.len() - self.index < length {
            if !self.eof {
                self.update_raw();
            }
            let data = self.raw.take().unwrap_or_default();
            if let Some(offset) = data.iter().position(|c| is_non_printable(*c)) {
                self.error = Some((self.buffer.len() + offset, u32::from(data[offset])));
                return;
            }
            self.buffer.extend_from_slice(&data);
            if self.eof {
                self.buffer.push('\0');
                self.raw = None;
                break;
            }
            self.raw = Some(Vec::new());
        }
    }

    pub(crate) fn peek(&mut self, index: usize) -> char {
        if self.index + index >= self.buffer.len() {
            self.update(index + 1);
        }
        if self.error.is_some() {
            return '\0';
        }
        self.buffer.get(self.index + index).copied().unwrap_or('\0')
    }

    pub(crate) fn prefix(&mut self, length: usize) -> String {
        if self.index + length >= self.buffer.len() {
            self.update(length);
        }
        if self.error.is_some() {
            return String::new();
        }
        let end = (self.index + length).min(self.buffer.len());
        self.buffer[self.index.min(end)..end].iter().collect()
    }

    pub(crate) fn forward(&mut self, length: usize) {
        if self.index + length + 1 >= self.buffer.len() {
            self.update(length + 1);
        }
        if self.error.is_some() {
            return;
        }
        for _ in 0..length {
            let Some(&ch) = self.buffer.get(self.index) else {
                return;
            };
            self.index += 1;
            let next = self.buffer.get(self.index).copied();
            if matches!(ch, '\n' | '\u{85}' | '\u{2028}' | '\u{2029}')
                || (ch == '\r' && next != Some('\n'))
            {
                self.line += 1;
                self.column = 0;
            } else if ch != '\u{FEFF}' {
                self.column += 1;
            }
        }
    }

    pub(crate) fn get_mark(&self) -> Mark {
        Mark {
            line: self.line,
            column: self.column,
        }
    }
}
