//! `yaml/scanner.py`.

use std::collections::{BTreeMap, VecDeque};

use super::reader::Reader;
use super::{Error, Mark, MarkedError};
use crate::python::str_repr;

const NUL_BLANK_BREAK: &str = "\0 \t\r\n\u{85}\u{2028}\u{2029}";
const NUL_SPACE_BREAK: &str = "\0 \r\n\u{85}\u{2028}\u{2029}";
const NUL_BREAK: &str = "\0\r\n\u{85}\u{2028}\u{2029}";
const BREAK: &str = "\r\n\u{85}\u{2028}\u{2029}";

#[derive(Clone, Debug)]
pub(crate) enum DirectiveValue {
    /// The major version; PyYAML ignores the minor one.
    Yaml(u64),
    Tag(String, String),
    None,
}

#[derive(Clone, Debug)]
pub(crate) enum TokenKind {
    Directive { name: String, value: DirectiveValue },
    DocumentStart,
    DocumentEnd,
    StreamStart,
    StreamEnd,
    BlockSequenceStart,
    BlockMappingStart,
    BlockEnd,
    FlowSequenceStart,
    FlowMappingStart,
    FlowSequenceEnd,
    FlowMappingEnd,
    Key,
    Value,
    BlockEntry,
    FlowEntry,
    Alias(String),
    Anchor(String),
    Tag(Option<String>, String),
    Scalar { value: String, plain: bool },
}

impl TokenKind {
    /// The token's `id`, as shown in parser errors.
    pub(crate) fn id(&self) -> &'static str {
        match self {
            TokenKind::Directive { .. } => "<directive>",
            TokenKind::DocumentStart => "<document start>",
            TokenKind::DocumentEnd => "<document end>",
            TokenKind::StreamStart => "<stream start>",
            TokenKind::StreamEnd => "<stream end>",
            TokenKind::BlockSequenceStart => "<block sequence start>",
            TokenKind::BlockMappingStart => "<block mapping start>",
            TokenKind::BlockEnd => "<block end>",
            TokenKind::FlowSequenceStart => "[",
            TokenKind::FlowMappingStart => "{",
            TokenKind::FlowSequenceEnd => "]",
            TokenKind::FlowMappingEnd => "}",
            TokenKind::Key => "?",
            TokenKind::Value => ":",
            TokenKind::BlockEntry => "-",
            TokenKind::FlowEntry => ",",
            TokenKind::Alias(_) => "<alias>",
            TokenKind::Anchor(_) => "<anchor>",
            TokenKind::Tag(..) => "<tag>",
            TokenKind::Scalar { .. } => "<scalar>",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Token {
    pub(crate) kind: TokenKind,
    pub(crate) start_mark: Mark,
    pub(crate) end_mark: Mark,
}

#[derive(Clone, Debug)]
struct SimpleKey {
    token_number: usize,
    required: bool,
    index: usize,
    line: usize,
    column: usize,
    mark: Mark,
}

type Result<T> = std::result::Result<T, Error>;

fn scanner_error(
    context: Option<&str>,
    context_mark: Option<Mark>,
    problem: impl Into<String>,
    problem_mark: Mark,
) -> Error {
    Error::Marked(MarkedError::new(
        context,
        context_mark,
        problem,
        Some(problem_mark),
    ))
}

fn repr_char(c: char) -> String {
    str_repr(&c.to_string())
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

pub(crate) struct Scanner {
    pub(crate) reader: Reader,
    done: bool,
    flow_level: usize,
    tokens: VecDeque<Token>,
    tokens_taken: usize,
    indent: isize,
    indents: Vec<isize>,
    allow_simple_key: bool,
    possible_simple_keys: BTreeMap<usize, SimpleKey>,
}

impl Scanner {
    pub(crate) fn new(reader: Reader) -> Self {
        let mut scanner = Scanner {
            reader,
            done: false,
            flow_level: 0,
            tokens: VecDeque::new(),
            tokens_taken: 0,
            indent: -1,
            indents: Vec::new(),
            allow_simple_key: true,
            possible_simple_keys: BTreeMap::new(),
        };
        let mark = scanner.reader.get_mark();
        scanner.tokens.push_back(Token {
            kind: TokenKind::StreamStart,
            start_mark: mark,
            end_mark: mark,
        });
        scanner
    }

    fn peek(&mut self, i: usize) -> char {
        self.reader.peek(i)
    }

    fn ch(&mut self) -> char {
        self.reader.peek(0)
    }

    fn forward(&mut self, n: usize) {
        self.reader.forward(n);
    }

    fn mark(&self) -> Mark {
        self.reader.get_mark()
    }

    fn column(&self) -> usize {
        self.reader.column
    }

    fn icolumn(&self) -> isize {
        isize::try_from(self.reader.column).unwrap_or(isize::MAX)
    }

    // Public methods.

    pub(crate) fn peek_token(&mut self) -> Result<Option<&Token>> {
        while self.need_more_tokens()? {
            self.fetch_more_tokens()?;
        }
        Ok(self.tokens.front())
    }

    pub(crate) fn get_token(&mut self) -> Result<Option<Token>> {
        while self.need_more_tokens()? {
            self.fetch_more_tokens()?;
        }
        let token = self.tokens.pop_front();
        if token.is_some() {
            self.tokens_taken += 1;
        }
        Ok(token)
    }

    // Private methods.

    fn need_more_tokens(&mut self) -> Result<bool> {
        if self.done {
            return Ok(false);
        }
        if self.tokens.is_empty() {
            return Ok(true);
        }
        self.stale_possible_simple_keys()?;
        Ok(self.next_possible_simple_key() == Some(self.tokens_taken))
    }

    fn fetch_more_tokens(&mut self) -> Result<()> {
        self.scan_to_next_token();
        self.stale_possible_simple_keys()?;
        self.unwind_indent(self.icolumn());
        let ch = self.ch();
        if ch == '\0' {
            return self.fetch_stream_end();
        }
        if ch == '%' && self.check_directive() {
            return self.fetch_directive();
        }
        if ch == '-' && self.check_document_start() {
            return self.fetch_document_indicator(TokenKind::DocumentStart);
        }
        if ch == '.' && self.check_document_end() {
            return self.fetch_document_indicator(TokenKind::DocumentEnd);
        }
        match ch {
            '[' => return self.fetch_flow_collection_start(TokenKind::FlowSequenceStart),
            '{' => return self.fetch_flow_collection_start(TokenKind::FlowMappingStart),
            ']' => return self.fetch_flow_collection_end(TokenKind::FlowSequenceEnd),
            '}' => return self.fetch_flow_collection_end(TokenKind::FlowMappingEnd),
            ',' => return self.fetch_flow_entry(),
            _ => {}
        }
        if ch == '-' && self.check_block_entry() {
            return self.fetch_block_entry();
        }
        if ch == '?' && self.check_key() {
            return self.fetch_key();
        }
        if ch == ':' && self.check_value() {
            return self.fetch_value();
        }
        match ch {
            '*' => return self.fetch_anchor(true),
            '&' => return self.fetch_anchor(false),
            '!' => return self.fetch_tag(),
            '|' if self.flow_level == 0 => return self.fetch_block_scalar('|'),
            '>' if self.flow_level == 0 => return self.fetch_block_scalar('>'),
            '\'' => return self.fetch_flow_scalar('\''),
            '"' => return self.fetch_flow_scalar('"'),
            _ => {}
        }
        if self.check_plain() {
            return self.fetch_plain();
        }
        Err(scanner_error(
            Some("while scanning for the next token"),
            None,
            format!(
                "found character {} that cannot start any token",
                repr_char(ch)
            ),
            self.mark(),
        ))
    }

    // Simple keys treatment.

    fn next_possible_simple_key(&self) -> Option<usize> {
        self.possible_simple_keys
            .values()
            .map(|k| k.token_number)
            .min()
    }

    fn stale_possible_simple_keys(&mut self) -> Result<()> {
        let levels: Vec<usize> = self.possible_simple_keys.keys().copied().collect();
        for level in levels {
            let Some(key) = self.possible_simple_keys.get(&level) else {
                continue;
            };
            if key.line != self.reader.line || self.reader.index - key.index > 1024 {
                if key.required {
                    return Err(scanner_error(
                        Some("while scanning a simple key"),
                        Some(key.mark),
                        "could not find expected ':'",
                        self.mark(),
                    ));
                }
                self.possible_simple_keys.remove(&level);
            }
        }
        Ok(())
    }

    fn save_possible_simple_key(&mut self) -> Result<()> {
        let required = self.flow_level == 0 && self.indent == self.icolumn();
        if self.allow_simple_key {
            self.remove_possible_simple_key()?;
            let token_number = self.tokens_taken + self.tokens.len();
            let key = SimpleKey {
                token_number,
                required,
                index: self.reader.index,
                line: self.reader.line,
                column: self.reader.column,
                mark: self.mark(),
            };
            self.possible_simple_keys.insert(self.flow_level, key);
        }
        Ok(())
    }

    fn remove_possible_simple_key(&mut self) -> Result<()> {
        if let Some(key) = self.possible_simple_keys.get(&self.flow_level) {
            if key.required {
                return Err(scanner_error(
                    Some("while scanning a simple key"),
                    Some(key.mark),
                    "could not find expected ':'",
                    self.mark(),
                ));
            }
            self.possible_simple_keys.remove(&self.flow_level);
        }
        Ok(())
    }

    // Indentation functions.

    fn unwind_indent(&mut self, column: isize) {
        if self.flow_level != 0 {
            return;
        }
        while self.indent > column {
            let mark = self.mark();
            self.indent = self.indents.pop().unwrap_or(-1);
            self.tokens.push_back(Token {
                kind: TokenKind::BlockEnd,
                start_mark: mark,
                end_mark: mark,
            });
        }
    }

    fn add_indent(&mut self, column: isize) -> bool {
        if self.indent < column {
            self.indents.push(self.indent);
            self.indent = column;
            return true;
        }
        false
    }

    // Fetchers.

    fn push(&mut self, kind: TokenKind, start_mark: Mark, end_mark: Mark) {
        self.tokens.push_back(Token {
            kind,
            start_mark,
            end_mark,
        });
    }

    fn fetch_stream_end(&mut self) -> Result<()> {
        self.unwind_indent(-1);
        self.remove_possible_simple_key()?;
        self.allow_simple_key = false;
        self.possible_simple_keys.clear();
        let mark = self.mark();
        self.push(TokenKind::StreamEnd, mark, mark);
        self.done = true;
        Ok(())
    }

    fn fetch_directive(&mut self) -> Result<()> {
        self.unwind_indent(-1);
        self.remove_possible_simple_key()?;
        self.allow_simple_key = false;
        let token = self.scan_directive()?;
        self.tokens.push_back(token);
        Ok(())
    }

    fn fetch_document_indicator(&mut self, kind: TokenKind) -> Result<()> {
        self.unwind_indent(-1);
        self.remove_possible_simple_key()?;
        self.allow_simple_key = false;
        let start = self.mark();
        self.forward(3);
        let end = self.mark();
        self.push(kind, start, end);
        Ok(())
    }

    fn fetch_flow_collection_start(&mut self, kind: TokenKind) -> Result<()> {
        self.save_possible_simple_key()?;
        self.flow_level = self.flow_level.wrapping_add(1);
        self.allow_simple_key = true;
        let start = self.mark();
        self.forward(1);
        let end = self.mark();
        self.push(kind, start, end);
        Ok(())
    }

    fn fetch_flow_collection_end(&mut self, kind: TokenKind) -> Result<()> {
        self.remove_possible_simple_key()?;
        // Python happily lets this go negative; a stray closing bracket at
        // flow level 0 then behaves as if inside a flow collection.
        self.flow_level = self.flow_level.wrapping_sub(1);
        self.allow_simple_key = false;
        let start = self.mark();
        self.forward(1);
        let end = self.mark();
        self.push(kind, start, end);
        Ok(())
    }

    fn fetch_flow_entry(&mut self) -> Result<()> {
        self.allow_simple_key = true;
        self.remove_possible_simple_key()?;
        let start = self.mark();
        self.forward(1);
        let end = self.mark();
        self.push(TokenKind::FlowEntry, start, end);
        Ok(())
    }

    fn fetch_block_entry(&mut self) -> Result<()> {
        if self.flow_level == 0 {
            if !self.allow_simple_key {
                return Err(scanner_error(
                    None,
                    None,
                    "sequence entries are not allowed here",
                    self.mark(),
                ));
            }
            if self.add_indent(self.icolumn()) {
                let mark = self.mark();
                self.push(TokenKind::BlockSequenceStart, mark, mark);
            }
        }
        self.allow_simple_key = true;
        self.remove_possible_simple_key()?;
        let start = self.mark();
        self.forward(1);
        let end = self.mark();
        self.push(TokenKind::BlockEntry, start, end);
        Ok(())
    }

    fn fetch_key(&mut self) -> Result<()> {
        if self.flow_level == 0 {
            if !self.allow_simple_key {
                return Err(scanner_error(
                    None,
                    None,
                    "mapping keys are not allowed here",
                    self.mark(),
                ));
            }
            if self.add_indent(self.icolumn()) {
                let mark = self.mark();
                self.push(TokenKind::BlockMappingStart, mark, mark);
            }
        }
        self.allow_simple_key = self.flow_level == 0;
        self.remove_possible_simple_key()?;
        let start = self.mark();
        self.forward(1);
        let end = self.mark();
        self.push(TokenKind::Key, start, end);
        Ok(())
    }

    fn fetch_value(&mut self) -> Result<()> {
        if let Some(key) = self.possible_simple_keys.remove(&self.flow_level) {
            let pos = key.token_number - self.tokens_taken;
            self.tokens.insert(
                pos,
                Token {
                    kind: TokenKind::Key,
                    start_mark: key.mark,
                    end_mark: key.mark,
                },
            );
            if self.flow_level == 0 {
                let column = isize::try_from(key.column).unwrap_or(isize::MAX);
                if self.add_indent(column) {
                    self.tokens.insert(
                        pos,
                        Token {
                            kind: TokenKind::BlockMappingStart,
                            start_mark: key.mark,
                            end_mark: key.mark,
                        },
                    );
                }
            }
            self.allow_simple_key = false;
        } else {
            if self.flow_level == 0 && !self.allow_simple_key {
                return Err(scanner_error(
                    None,
                    None,
                    "mapping values are not allowed here",
                    self.mark(),
                ));
            }
            if self.flow_level == 0 && self.add_indent(self.icolumn()) {
                let mark = self.mark();
                self.push(TokenKind::BlockMappingStart, mark, mark);
            }
            self.allow_simple_key = self.flow_level == 0;
            self.remove_possible_simple_key()?;
        }
        let start = self.mark();
        self.forward(1);
        let end = self.mark();
        self.push(TokenKind::Value, start, end);
        Ok(())
    }

    fn fetch_anchor(&mut self, alias: bool) -> Result<()> {
        self.save_possible_simple_key()?;
        self.allow_simple_key = false;
        let token = self.scan_anchor(alias)?;
        self.tokens.push_back(token);
        Ok(())
    }

    fn fetch_tag(&mut self) -> Result<()> {
        self.save_possible_simple_key()?;
        self.allow_simple_key = false;
        let token = self.scan_tag()?;
        self.tokens.push_back(token);
        Ok(())
    }

    fn fetch_block_scalar(&mut self, style: char) -> Result<()> {
        self.allow_simple_key = true;
        self.remove_possible_simple_key()?;
        let token = self.scan_block_scalar(style)?;
        self.tokens.push_back(token);
        Ok(())
    }

    fn fetch_flow_scalar(&mut self, style: char) -> Result<()> {
        self.save_possible_simple_key()?;
        self.allow_simple_key = false;
        let token = self.scan_flow_scalar(style)?;
        self.tokens.push_back(token);
        Ok(())
    }

    fn fetch_plain(&mut self) -> Result<()> {
        self.save_possible_simple_key()?;
        self.allow_simple_key = false;
        let token = self.scan_plain()?;
        self.tokens.push_back(token);
        Ok(())
    }

    // Checkers.

    fn check_directive(&self) -> bool {
        self.column() == 0
    }

    fn check_document_start(&mut self) -> bool {
        self.column() == 0
            && self.reader.prefix(3) == "---"
            && NUL_BLANK_BREAK.contains(self.peek(3))
    }

    fn check_document_end(&mut self) -> bool {
        self.column() == 0
            && self.reader.prefix(3) == "..."
            && NUL_BLANK_BREAK.contains(self.peek(3))
    }

    fn check_block_entry(&mut self) -> bool {
        NUL_BLANK_BREAK.contains(self.peek(1))
    }

    fn check_key(&mut self) -> bool {
        self.flow_level != 0 || NUL_BLANK_BREAK.contains(self.peek(1))
    }

    fn check_value(&mut self) -> bool {
        self.flow_level != 0 || NUL_BLANK_BREAK.contains(self.peek(1))
    }

    fn check_plain(&mut self) -> bool {
        let ch = self.ch();
        let excluded = "\0 \t\r\n\u{85}\u{2028}\u{2029}-?:,[]{}#&*!|>'\"%@`";
        !excluded.contains(ch)
            || (!NUL_BLANK_BREAK.contains(self.peek(1))
                && (ch == '-' || (self.flow_level == 0 && "?:".contains(ch))))
    }

    // Scanners.

    fn scan_to_next_token(&mut self) {
        if self.reader.index == 0 && self.ch() == '\u{FEFF}' {
            self.forward(1);
        }
        loop {
            while self.ch() == ' ' {
                self.forward(1);
            }
            if self.ch() == '#' {
                while !NUL_BREAK.contains(self.ch()) {
                    self.forward(1);
                }
            }
            if self.scan_line_break().is_empty() {
                break;
            }
            if self.flow_level == 0 {
                self.allow_simple_key = true;
            }
        }
    }

    fn scan_directive(&mut self) -> Result<Token> {
        let start_mark = self.mark();
        self.forward(1);
        let name = self.scan_directive_name(start_mark)?;
        let value;
        let end_mark;
        if name == "YAML" {
            value = self.scan_yaml_directive_value(start_mark)?;
            end_mark = self.mark();
        } else if name == "TAG" {
            value = self.scan_tag_directive_value(start_mark)?;
            end_mark = self.mark();
        } else {
            value = DirectiveValue::None;
            end_mark = self.mark();
            while !NUL_BREAK.contains(self.ch()) {
                self.forward(1);
            }
        }
        self.scan_directive_ignored_line(start_mark)?;
        Ok(Token {
            kind: TokenKind::Directive { name, value },
            start_mark,
            end_mark,
        })
    }

    fn directive_error(&self, start_mark: Mark, problem: String) -> Error {
        scanner_error(
            Some("while scanning a directive"),
            Some(start_mark),
            problem,
            self.mark(),
        )
    }

    fn scan_directive_name(&mut self, start_mark: Mark) -> Result<String> {
        let mut length = 0;
        let mut ch = self.peek(length);
        while is_word_char(ch) {
            length += 1;
            ch = self.peek(length);
        }
        if length == 0 {
            return Err(self.directive_error(
                start_mark,
                format!(
                    "expected alphabetic or numeric character, but found {}",
                    repr_char(ch)
                ),
            ));
        }
        let value = self.reader.prefix(length);
        self.forward(length);
        let ch = self.ch();
        if !NUL_SPACE_BREAK.contains(ch) {
            return Err(self.directive_error(
                start_mark,
                format!(
                    "expected alphabetic or numeric character, but found {}",
                    repr_char(ch)
                ),
            ));
        }
        Ok(value)
    }

    fn scan_yaml_directive_value(&mut self, start_mark: Mark) -> Result<DirectiveValue> {
        while self.ch() == ' ' {
            self.forward(1);
        }
        let major = self.scan_yaml_directive_number(start_mark)?;
        if self.ch() != '.' {
            let ch = self.ch();
            return Err(self.directive_error(
                start_mark,
                format!("expected a digit or '.', but found {}", repr_char(ch)),
            ));
        }
        self.forward(1);
        let _minor = self.scan_yaml_directive_number(start_mark)?;
        if !NUL_SPACE_BREAK.contains(self.ch()) {
            let ch = self.ch();
            return Err(self.directive_error(
                start_mark,
                format!("expected a digit or ' ', but found {}", repr_char(ch)),
            ));
        }
        Ok(DirectiveValue::Yaml(major))
    }

    fn scan_yaml_directive_number(&mut self, start_mark: Mark) -> Result<u64> {
        let ch = self.ch();
        if !ch.is_ascii_digit() {
            return Err(self.directive_error(
                start_mark,
                format!("expected a digit, but found {}", repr_char(ch)),
            ));
        }
        let mut length = 0;
        while self.peek(length).is_ascii_digit() {
            length += 1;
        }
        let text = self.reader.prefix(length);
        // Python ints are unbounded; anything this large is not version 1.
        let value = text.parse::<u64>().unwrap_or(u64::MAX);
        self.forward(length);
        Ok(value)
    }

    fn scan_tag_directive_value(&mut self, start_mark: Mark) -> Result<DirectiveValue> {
        while self.ch() == ' ' {
            self.forward(1);
        }
        let handle = self.scan_tag_handle("directive", start_mark)?;
        if self.ch() != ' ' {
            let ch = self.ch();
            return Err(self.directive_error(
                start_mark,
                format!("expected ' ', but found {}", repr_char(ch)),
            ));
        }
        while self.ch() == ' ' {
            self.forward(1);
        }
        let prefix = self.scan_tag_uri("directive", start_mark)?;
        if !NUL_SPACE_BREAK.contains(self.ch()) {
            let ch = self.ch();
            return Err(self.directive_error(
                start_mark,
                format!("expected ' ', but found {}", repr_char(ch)),
            ));
        }
        Ok(DirectiveValue::Tag(handle, prefix))
    }

    fn scan_directive_ignored_line(&mut self, start_mark: Mark) -> Result<()> {
        while self.ch() == ' ' {
            self.forward(1);
        }
        if self.ch() == '#' {
            while !NUL_BREAK.contains(self.ch()) {
                self.forward(1);
            }
        }
        let ch = self.ch();
        if !NUL_BREAK.contains(ch) {
            return Err(self.directive_error(
                start_mark,
                format!(
                    "expected a comment or a line break, but found {}",
                    repr_char(ch)
                ),
            ));
        }
        self.scan_line_break();
        Ok(())
    }

    fn scan_anchor(&mut self, alias: bool) -> Result<Token> {
        let start_mark = self.mark();
        let name = if alias { "alias" } else { "anchor" };
        self.forward(1);
        let mut length = 0;
        let mut ch = self.peek(length);
        while is_word_char(ch) {
            length += 1;
            ch = self.peek(length);
        }
        let err = |s: &Self, ch: char| {
            scanner_error(
                Some(&format!("while scanning an {name}")),
                Some(start_mark),
                format!(
                    "expected alphabetic or numeric character, but found {}",
                    repr_char(ch)
                ),
                s.mark(),
            )
        };
        if length == 0 {
            return Err(err(self, ch));
        }
        let value = self.reader.prefix(length);
        self.forward(length);
        let ch = self.ch();
        if !"\0 \t\r\n\u{85}\u{2028}\u{2029}?:,]}%@`".contains(ch) {
            return Err(err(self, ch));
        }
        let end_mark = self.mark();
        let kind = if alias {
            TokenKind::Alias(value)
        } else {
            TokenKind::Anchor(value)
        };
        Ok(Token {
            kind,
            start_mark,
            end_mark,
        })
    }

    fn scan_tag(&mut self) -> Result<Token> {
        let start_mark = self.mark();
        let mut ch = self.peek(1);
        let handle;
        let suffix;
        if ch == '<' {
            handle = None;
            self.forward(2);
            suffix = self.scan_tag_uri("tag", start_mark)?;
            if self.ch() != '>' {
                let c = self.ch();
                return Err(scanner_error(
                    Some("while parsing a tag"),
                    Some(start_mark),
                    format!("expected '>', but found {}", repr_char(c)),
                    self.mark(),
                ));
            }
            self.forward(1);
        } else if NUL_BLANK_BREAK.contains(ch) {
            handle = None;
            suffix = "!".to_owned();
            self.forward(1);
        } else {
            let mut length = 1;
            let mut use_handle = false;
            while !NUL_SPACE_BREAK.contains(ch) {
                if ch == '!' {
                    use_handle = true;
                    break;
                }
                length += 1;
                ch = self.peek(length);
            }
            if use_handle {
                handle = Some(self.scan_tag_handle("tag", start_mark)?);
            } else {
                handle = Some("!".to_owned());
                self.forward(1);
            }
            suffix = self.scan_tag_uri("tag", start_mark)?;
        }
        let ch = self.ch();
        if !NUL_SPACE_BREAK.contains(ch) {
            return Err(scanner_error(
                Some("while scanning a tag"),
                Some(start_mark),
                format!("expected ' ', but found {}", repr_char(ch)),
                self.mark(),
            ));
        }
        let end_mark = self.mark();
        Ok(Token {
            kind: TokenKind::Tag(handle, suffix),
            start_mark,
            end_mark,
        })
    }

    fn scan_block_scalar(&mut self, style: char) -> Result<Token> {
        let folded = style == '>';
        let mut chunks: Vec<String> = Vec::new();
        let start_mark = self.mark();
        self.forward(1);
        let (chomping, increment) = self.scan_block_scalar_indicators(start_mark)?;
        self.scan_block_scalar_ignored_line(start_mark)?;
        let mut min_indent = self.indent + 1;
        if min_indent < 1 {
            min_indent = 1;
        }
        let indent;
        let mut breaks;
        let mut end_mark;
        match increment {
            None => {
                let (b, max_indent, e) = self.scan_block_scalar_indentation();
                breaks = b;
                end_mark = e;
                indent = min_indent.max(max_indent);
            }
            Some(inc) => {
                indent = min_indent + inc - 1;
                let (b, e) = self.scan_block_scalar_breaks(indent);
                breaks = b;
                end_mark = e;
            }
        }
        let mut line_break = String::new();
        while self.icolumn() == indent && self.ch() != '\0' {
            chunks.append(&mut breaks);
            let leading_non_space = !" \t".contains(self.ch());
            let mut length = 0;
            while !NUL_BREAK.contains(self.peek(length)) {
                length += 1;
            }
            chunks.push(self.reader.prefix(length));
            self.forward(length);
            line_break = self.scan_line_break();
            let (b, e) = self.scan_block_scalar_breaks(indent);
            breaks = b;
            end_mark = e;
            if self.icolumn() == indent && self.ch() != '\0' {
                if folded && line_break == "\n" && leading_non_space && !" \t".contains(self.ch()) {
                    if breaks.is_empty() {
                        chunks.push(" ".to_owned());
                    }
                } else {
                    chunks.push(line_break.clone());
                }
            } else {
                break;
            }
        }
        if chomping != Some(false) {
            chunks.push(line_break);
        }
        if chomping == Some(true) {
            chunks.append(&mut breaks);
        }
        Ok(Token {
            kind: TokenKind::Scalar {
                value: chunks.concat(),
                plain: false,
            },
            start_mark,
            end_mark,
        })
    }

    fn scan_block_scalar_indicators(
        &mut self,
        start_mark: Mark,
    ) -> Result<(Option<bool>, Option<isize>)> {
        let mut chomping = None;
        let mut increment = None;
        let zero_error = |s: &Self| {
            scanner_error(
                Some("while scanning a block scalar"),
                Some(start_mark),
                "expected indentation indicator in the range 1-9, but found 0",
                s.mark(),
            )
        };
        let mut ch = self.ch();
        if ch == '+' || ch == '-' {
            chomping = Some(ch == '+');
            self.forward(1);
            ch = self.ch();
            if let Some(d) = ch.to_digit(10) {
                if d == 0 {
                    return Err(zero_error(self));
                }
                increment = Some(isize::try_from(d).unwrap_or(1));
                self.forward(1);
            }
        } else if let Some(d) = ch.to_digit(10) {
            if d == 0 {
                return Err(zero_error(self));
            }
            increment = Some(isize::try_from(d).unwrap_or(1));
            self.forward(1);
            ch = self.ch();
            if ch == '+' || ch == '-' {
                chomping = Some(ch == '+');
                self.forward(1);
            }
        }
        let ch = self.ch();
        if !NUL_SPACE_BREAK.contains(ch) {
            return Err(scanner_error(
                Some("while scanning a block scalar"),
                Some(start_mark),
                format!(
                    "expected chomping or indentation indicators, but found {}",
                    repr_char(ch)
                ),
                self.mark(),
            ));
        }
        Ok((chomping, increment))
    }

    fn scan_block_scalar_ignored_line(&mut self, start_mark: Mark) -> Result<()> {
        while self.ch() == ' ' {
            self.forward(1);
        }
        if self.ch() == '#' {
            while !NUL_BREAK.contains(self.ch()) {
                self.forward(1);
            }
        }
        let ch = self.ch();
        if !NUL_BREAK.contains(ch) {
            return Err(scanner_error(
                Some("while scanning a block scalar"),
                Some(start_mark),
                format!(
                    "expected a comment or a line break, but found {}",
                    repr_char(ch)
                ),
                self.mark(),
            ));
        }
        self.scan_line_break();
        Ok(())
    }

    fn scan_block_scalar_indentation(&mut self) -> (Vec<String>, isize, Mark) {
        let mut chunks = Vec::new();
        let mut max_indent = 0;
        let mut end_mark = self.mark();
        while " \r\n\u{85}\u{2028}\u{2029}".contains(self.ch()) {
            if self.ch() != ' ' {
                chunks.push(self.scan_line_break());
                end_mark = self.mark();
            } else {
                self.forward(1);
                if self.icolumn() > max_indent {
                    max_indent = self.icolumn();
                }
            }
        }
        (chunks, max_indent, end_mark)
    }

    fn scan_block_scalar_breaks(&mut self, indent: isize) -> (Vec<String>, Mark) {
        let mut chunks = Vec::new();
        let mut end_mark = self.mark();
        while self.icolumn() < indent && self.ch() == ' ' {
            self.forward(1);
        }
        while BREAK.contains(self.ch()) {
            chunks.push(self.scan_line_break());
            end_mark = self.mark();
            while self.icolumn() < indent && self.ch() == ' ' {
                self.forward(1);
            }
        }
        (chunks, end_mark)
    }

    fn scan_flow_scalar(&mut self, style: char) -> Result<Token> {
        let double = style == '"';
        let mut chunks = Vec::new();
        let start_mark = self.mark();
        let quote = self.ch();
        self.forward(1);
        chunks.extend(self.scan_flow_scalar_non_spaces(double, start_mark)?);
        while self.ch() != quote {
            chunks.extend(self.scan_flow_scalar_spaces(double, start_mark)?);
            chunks.extend(self.scan_flow_scalar_non_spaces(double, start_mark)?);
        }
        self.forward(1);
        let end_mark = self.mark();
        Ok(Token {
            kind: TokenKind::Scalar {
                value: chunks.concat(),
                plain: false,
            },
            start_mark,
            end_mark,
        })
    }

    fn scan_flow_scalar_non_spaces(
        &mut self,
        double: bool,
        start_mark: Mark,
    ) -> Result<Vec<String>> {
        let mut chunks = Vec::new();
        loop {
            let mut length = 0;
            while !"'\"\\\0 \t\r\n\u{85}\u{2028}\u{2029}".contains(self.peek(length)) {
                length += 1;
            }
            if length > 0 {
                chunks.push(self.reader.prefix(length));
                self.forward(length);
            }
            let ch = self.ch();
            if !double && ch == '\'' && self.peek(1) == '\'' {
                chunks.push("'".to_owned());
                self.forward(2);
            } else if (double && ch == '\'') || (!double && (ch == '"' || ch == '\\')) {
                chunks.push(ch.to_string());
                self.forward(1);
            } else if double && ch == '\\' {
                self.forward(1);
                let ch = self.ch();
                let replacement = match ch {
                    '0' => Some('\0'),
                    'a' => Some('\x07'),
                    'b' => Some('\x08'),
                    't' | '\t' => Some('\x09'),
                    'n' => Some('\x0A'),
                    'v' => Some('\x0B'),
                    'f' => Some('\x0C'),
                    'r' => Some('\x0D'),
                    'e' => Some('\x1B'),
                    ' ' => Some('\x20'),
                    '"' => Some('"'),
                    '\\' => Some('\\'),
                    '/' => Some('/'),
                    'N' => Some('\u{85}'),
                    '_' => Some('\u{A0}'),
                    'L' => Some('\u{2028}'),
                    'P' => Some('\u{2029}'),
                    _ => None,
                };
                let code_length = match ch {
                    'x' => Some(2),
                    'u' => Some(4),
                    'U' => Some(8),
                    _ => None,
                };
                if let Some(r) = replacement {
                    chunks.push(r.to_string());
                    self.forward(1);
                } else if let Some(length) = code_length {
                    self.forward(1);
                    for k in 0..length {
                        let c = self.peek(k);
                        if !c.is_ascii_hexdigit() {
                            return Err(scanner_error(
                                Some("while scanning a double-quoted scalar"),
                                Some(start_mark),
                                format!(
                                    "expected escape sequence of {length} hexadecimal numbers, but found {}",
                                    repr_char(c)
                                ),
                                self.mark(),
                            ));
                        }
                    }
                    let hex = self.reader.prefix(length);
                    let code = u32::from_str_radix(&hex, 16).unwrap_or(0);
                    let c = match char::from_u32(code) {
                        Some(c) => c,
                        None if code > 0x10FFFF => {
                            return Err(Error::Crash(crate::python::PyException::value_error(
                                "chr() arg not in range(0x110000)",
                            )));
                        }
                        // A lone surrogate: Python keeps it, Rust strings cannot.
                        None => '\u{FFFD}',
                    };
                    chunks.push(c.to_string());
                    self.forward(length);
                } else if BREAK.contains(ch) {
                    self.scan_line_break();
                    chunks.extend(self.scan_flow_scalar_breaks(start_mark)?);
                } else {
                    return Err(scanner_error(
                        Some("while scanning a double-quoted scalar"),
                        Some(start_mark),
                        format!("found unknown escape character {}", repr_char(ch)),
                        self.mark(),
                    ));
                }
            } else {
                return Ok(chunks);
            }
        }
    }

    fn scan_flow_scalar_spaces(&mut self, _double: bool, start_mark: Mark) -> Result<Vec<String>> {
        let mut chunks = Vec::new();
        let mut length = 0;
        while " \t".contains(self.peek(length)) {
            length += 1;
        }
        let whitespaces = self.reader.prefix(length);
        self.forward(length);
        let ch = self.ch();
        if ch == '\0' {
            return Err(scanner_error(
                Some("while scanning a quoted scalar"),
                Some(start_mark),
                "found unexpected end of stream",
                self.mark(),
            ));
        } else if BREAK.contains(ch) {
            let line_break = self.scan_line_break();
            let breaks = self.scan_flow_scalar_breaks(start_mark)?;
            if line_break != "\n" {
                chunks.push(line_break);
            } else if breaks.is_empty() {
                chunks.push(" ".to_owned());
            }
            chunks.extend(breaks);
        } else {
            chunks.push(whitespaces);
        }
        Ok(chunks)
    }

    fn scan_flow_scalar_breaks(&mut self, start_mark: Mark) -> Result<Vec<String>> {
        let mut chunks = Vec::new();
        loop {
            let prefix = self.reader.prefix(3);
            if (prefix == "---" || prefix == "...") && NUL_BLANK_BREAK.contains(self.peek(3)) {
                return Err(scanner_error(
                    Some("while scanning a quoted scalar"),
                    Some(start_mark),
                    "found unexpected document separator",
                    self.mark(),
                ));
            }
            while " \t".contains(self.ch()) {
                self.forward(1);
            }
            if BREAK.contains(self.ch()) {
                chunks.push(self.scan_line_break());
            } else {
                return Ok(chunks);
            }
        }
    }

    fn scan_plain(&mut self) -> Result<Token> {
        let mut chunks: Vec<String> = Vec::new();
        let start_mark = self.mark();
        let mut end_mark = start_mark;
        let indent = self.indent + 1;
        let mut spaces: Vec<String> = Vec::new();
        loop {
            let mut length = 0;
            if self.ch() == '#' {
                break;
            }
            loop {
                let ch = self.peek(length);
                let stop = NUL_BLANK_BREAK.contains(ch)
                    || (ch == ':' && {
                        let next = self.peek(length + 1);
                        NUL_BLANK_BREAK.contains(next)
                            || (self.flow_level != 0 && ",[]{}".contains(next))
                    })
                    || (self.flow_level != 0 && ",?[]{}".contains(ch));
                if stop {
                    break;
                }
                length += 1;
            }
            if length == 0 {
                break;
            }
            self.allow_simple_key = false;
            chunks.append(&mut spaces);
            chunks.push(self.reader.prefix(length));
            self.forward(length);
            end_mark = self.mark();
            match self.scan_plain_spaces() {
                None => break,
                Some(s) => {
                    spaces = s;
                    if spaces.is_empty()
                        || self.ch() == '#'
                        || (self.flow_level == 0 && self.icolumn() < indent)
                    {
                        break;
                    }
                }
            }
        }
        Ok(Token {
            kind: TokenKind::Scalar {
                value: chunks.concat(),
                plain: true,
            },
            start_mark,
            end_mark,
        })
    }

    /// Returns `None` where Python's version returns `None` (a document
    /// separator follows), which ends the plain scalar.
    fn scan_plain_spaces(&mut self) -> Option<Vec<String>> {
        let mut chunks = Vec::new();
        let mut length = 0;
        while self.peek(length) == ' ' {
            length += 1;
        }
        let whitespaces = self.reader.prefix(length);
        self.forward(length);
        let ch = self.ch();
        if BREAK.contains(ch) {
            let line_break = self.scan_line_break();
            self.allow_simple_key = true;
            let prefix = self.reader.prefix(3);
            if (prefix == "---" || prefix == "...") && NUL_BLANK_BREAK.contains(self.peek(3)) {
                return None;
            }
            let mut breaks = Vec::new();
            while " \r\n\u{85}\u{2028}\u{2029}".contains(self.ch()) {
                if self.ch() == ' ' {
                    self.forward(1);
                } else {
                    breaks.push(self.scan_line_break());
                    let prefix = self.reader.prefix(3);
                    if (prefix == "---" || prefix == "...")
                        && NUL_BLANK_BREAK.contains(self.peek(3))
                    {
                        return None;
                    }
                }
            }
            if line_break != "\n" {
                chunks.push(line_break);
            } else if breaks.is_empty() {
                chunks.push(" ".to_owned());
            }
            chunks.extend(breaks);
        } else if !whitespaces.is_empty() {
            chunks.push(whitespaces);
        }
        Some(chunks)
    }

    fn scan_tag_handle(&mut self, name: &str, start_mark: Mark) -> Result<String> {
        let err = |s: &Self, ch: char| {
            scanner_error(
                Some(&format!("while scanning a {name}")),
                Some(start_mark),
                format!("expected '!', but found {}", repr_char(ch)),
                s.mark(),
            )
        };
        let ch = self.ch();
        if ch != '!' {
            return Err(err(self, ch));
        }
        let mut length = 1;
        let mut ch = self.peek(length);
        if ch != ' ' {
            while is_word_char(ch) {
                length += 1;
                ch = self.peek(length);
            }
            if ch != '!' {
                self.forward(length);
                return Err(err(self, ch));
            }
            length += 1;
        }
        let value = self.reader.prefix(length);
        self.forward(length);
        Ok(value)
    }

    fn scan_tag_uri(&mut self, name: &str, start_mark: Mark) -> Result<String> {
        let mut chunks = Vec::new();
        let mut length = 0;
        let mut ch = self.peek(length);
        while ch.is_ascii_alphanumeric() || "-;/?:@&=+$,_.!~*'()[]%".contains(ch) {
            if ch == '%' {
                chunks.push(self.reader.prefix(length));
                self.forward(length);
                length = 0;
                chunks.push(self.scan_uri_escapes(name, start_mark)?);
            } else {
                length += 1;
            }
            ch = self.peek(length);
        }
        if length > 0 {
            chunks.push(self.reader.prefix(length));
            self.forward(length);
        }
        if chunks.is_empty() {
            return Err(scanner_error(
                Some(&format!("while parsing a {name}")),
                Some(start_mark),
                format!("expected URI, but found {}", repr_char(ch)),
                self.mark(),
            ));
        }
        Ok(chunks.concat())
    }

    fn scan_uri_escapes(&mut self, name: &str, start_mark: Mark) -> Result<String> {
        let mut codes = Vec::new();
        let mark = self.mark();
        while self.ch() == '%' {
            self.forward(1);
            for k in 0..2 {
                let c = self.peek(k);
                if !c.is_ascii_hexdigit() {
                    return Err(scanner_error(
                        Some(&format!("while scanning a {name}")),
                        Some(start_mark),
                        format!(
                            "expected URI escape sequence of 2 hexadecimal numbers, but found {}",
                            repr_char(c)
                        ),
                        self.mark(),
                    ));
                }
            }
            let hex = self.reader.prefix(2);
            codes.push(u8::from_str_radix(&hex, 16).unwrap_or(0));
            self.forward(2);
        }
        match String::from_utf8(codes.clone()) {
            Ok(s) => Ok(s),
            Err(e) => {
                let start = e.utf8_error().valid_up_to();
                let byte = codes.get(start).copied().unwrap_or(0);
                let reason = utf8_error_reason(&codes[start..]);
                Err(scanner_error(
                    Some(&format!("while scanning a {name}")),
                    Some(start_mark),
                    format!(
                        "'utf-8' codec can't decode byte 0x{byte:02x} in position {start}: {reason}"
                    ),
                    mark,
                ))
            }
        }
    }

    fn scan_line_break(&mut self) -> String {
        let ch = self.ch();
        if "\r\n\u{85}".contains(ch) {
            if self.reader.prefix(2) == "\r\n" {
                self.forward(2);
            } else {
                self.forward(1);
            }
            return "\n".to_owned();
        } else if "\u{2028}\u{2029}".contains(ch) {
            self.forward(1);
            return ch.to_string();
        }
        String::new()
    }
}

/// CPython's UTF-8 decoder error reason for the bytes starting at the
/// first invalid position.
pub(crate) fn utf8_error_reason(bytes: &[u8]) -> &'static str {
    let Some(&first) = bytes.first() else {
        return "unexpected end of data";
    };
    let needed = match first {
        0xC2..=0xDF => 1,
        0xE0..=0xEF => 2,
        0xF0..=0xF4 => 3,
        _ => return "invalid start byte",
    };
    for i in 1..=needed {
        match bytes.get(i) {
            None => return "unexpected end of data",
            Some(b) if b & 0xC0 != 0x80 => return "invalid continuation byte",
            Some(&b) => {
                if i == 1 {
                    let bad = match first {
                        0xE0 => b < 0xA0,
                        0xED => b > 0x9F,
                        0xF0 => b < 0x90,
                        0xF4 => b > 0x8F,
                        _ => false,
                    };
                    if bad {
                        return "invalid continuation byte";
                    }
                }
            }
        }
    }
    "invalid continuation byte"
}
