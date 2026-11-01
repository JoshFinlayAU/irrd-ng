//! graphql-core's lexer and parser (`language/lexer.py`, `parser.py`),
//! with their syntax error texts. Positions are character offsets, as in
//! Python.

use crate::ast::*;

/// `GraphQLSyntaxError`: a description and where it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxError {
    /// Character offset.
    pub pos: usize,
    /// The description (the message is `Syntax Error: {description}`).
    pub description: String,
}

type PResult<T> = Result<T, SyntaxError>;

/// `Source.get_location()`, including graphql-core's use of
/// `str.splitlines()`: a position just after a line break reports the end
/// of the previous line, and every character Python treats as a line
/// boundary counts.
pub fn location(body: &[char], pos: usize) -> (usize, usize) {
    let head = &body[..pos.min(body.len())];
    let mut lines = 0usize;
    let mut last_len = 0usize;
    let mut i = 0;
    let mut cur = 0usize;
    let mut any = false;
    while i < head.len() {
        let c = head[i];
        if matches!(
            c,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        ) {
            if c == '\r' && head.get(i + 1) == Some(&'\n') {
                i += 1;
            }
            lines += 1;
            last_len = cur;
            cur = 0;
            any = false;
        } else {
            cur += 1;
            any = true;
        }
        i += 1;
    }
    if any {
        lines += 1;
        last_len = cur;
    }
    if lines == 0 {
        (1, 1)
    } else {
        (lines, last_len + 1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Sof,
    Eof,
    Bang,
    Dollar,
    Amp,
    ParenL,
    ParenR,
    Spread,
    Colon,
    Equals,
    At,
    BracketL,
    BracketR,
    BraceL,
    Pipe,
    BraceR,
    Name,
    Int,
    Float,
    String,
    BlockString,
    Comment,
}

impl Kind {
    fn value(self) -> &'static str {
        match self {
            Kind::Sof => "<SOF>",
            Kind::Eof => "<EOF>",
            Kind::Bang => "!",
            Kind::Dollar => "$",
            Kind::Amp => "&",
            Kind::ParenL => "(",
            Kind::ParenR => ")",
            Kind::Spread => "...",
            Kind::Colon => ":",
            Kind::Equals => "=",
            Kind::At => "@",
            Kind::BracketL => "[",
            Kind::BracketR => "]",
            Kind::BraceL => "{",
            Kind::Pipe => "|",
            Kind::BraceR => "}",
            Kind::Name => "Name",
            Kind::Int => "Int",
            Kind::Float => "Float",
            Kind::String => "String",
            Kind::BlockString => "BlockString",
            Kind::Comment => "Comment",
        }
    }

    fn is_punctuator(self) -> bool {
        !matches!(
            self,
            Kind::Sof
                | Kind::Eof
                | Kind::Name
                | Kind::Int
                | Kind::Float
                | Kind::String
                | Kind::BlockString
                | Kind::Comment
        )
    }

    /// `get_token_kind_desc()`
    fn desc(self) -> String {
        if self.is_punctuator() {
            format!("'{}'", self.value())
        } else {
            self.value().to_owned()
        }
    }
}

#[derive(Debug, Clone)]
struct Token {
    kind: Kind,
    start: usize,
    end: usize,
    value: Option<String>,
}

impl Token {
    /// `get_token_desc()`
    fn desc(&self) -> String {
        match &self.value {
            Some(v) => format!("{} '{}'", self.kind.desc(), v),
            None => self.kind.desc(),
        }
    }
}

fn is_digit(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_ascii_digit())
}

fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_name_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn hex(c: Option<char>) -> i64 {
    match c {
        Some(c @ '0'..='9') => c as i64 - 48,
        Some(c @ 'A'..='F') => c as i64 - 55,
        Some(c @ 'a'..='f') => c as i64 - 87,
        _ => -1,
    }
}

struct Lexer<'a> {
    body: &'a [char],
    token: Token,
    /// Tokens already read ahead (lookahead without advancing).
    ahead: Option<Token>,
}

impl<'a> Lexer<'a> {
    fn new(body: &'a [char]) -> Self {
        Lexer {
            body,
            token: Token {
                kind: Kind::Sof,
                start: 0,
                end: 0,
                value: None,
            },
            ahead: None,
        }
    }

    fn err<T>(&self, pos: usize, d: impl Into<String>) -> PResult<T> {
        Err(SyntaxError {
            pos,
            description: d.into(),
        })
    }

    fn at(&self, i: usize) -> Option<char> {
        self.body.get(i).copied()
    }

    /// The end of a token, where the next read starts.
    fn end_of(&self, t: &Token) -> usize {
        t.end
    }

    fn advance(&mut self) -> PResult<()> {
        let next = match self.ahead.take() {
            Some(t) => t,
            None => self.lookahead_token()?,
        };
        self.token = next;
        Ok(())
    }

    fn lookahead(&mut self) -> PResult<Token> {
        if let Some(t) = &self.ahead {
            return Ok(t.clone());
        }
        let t = self.lookahead_token()?;
        self.ahead = Some(t.clone());
        Ok(t)
    }

    fn lookahead_token(&self) -> PResult<Token> {
        let mut t = self.token.clone();
        if t.kind == Kind::Eof {
            return Ok(t);
        }
        loop {
            let start = self.end_of(&t);
            t = self.read_next_token(start)?;
            if t.kind != Kind::Comment {
                return Ok(t);
            }
        }
    }

    fn tok(&self, kind: Kind, start: usize, end: usize, value: Option<String>) -> Token {
        Token {
            kind,
            start,
            end,
            value,
        }
    }

    fn print_code_point_at(&self, location: usize) -> String {
        match self.at(location) {
            None => Kind::Eof.value().to_owned(),
            Some('"') => "'\"'".to_owned(),
            Some(c) if ('\x20'..='\x7e').contains(&c) => format!("'{c}'"),
            Some(c) => format!("U+{:04X}", c as u32),
        }
    }

    fn read_next_token(&self, start: usize) -> PResult<Token> {
        let body = self.body;
        let len = body.len();
        let mut pos = start;
        while pos < len {
            let c = body[pos];
            match c {
                ' ' | '\t' | ',' | '\u{feff}' | '\n' | '\r' => {
                    pos += 1;
                    continue;
                }
                '#' => {
                    let mut p = pos + 1;
                    while p < len && !matches!(body[p], '\r' | '\n') {
                        p += 1;
                    }
                    let v: String = body[pos + 1..p].iter().collect();
                    return Ok(self.tok(Kind::Comment, pos, p, Some(v)));
                }
                '"' => {
                    if self.at(pos + 1) == Some('"') && self.at(pos + 2) == Some('"') {
                        return self.read_block_string(pos);
                    }
                    return self.read_string(pos);
                }
                _ => {}
            }
            let punct = match c {
                '!' => Some(Kind::Bang),
                '$' => Some(Kind::Dollar),
                '&' => Some(Kind::Amp),
                '(' => Some(Kind::ParenL),
                ')' => Some(Kind::ParenR),
                ':' => Some(Kind::Colon),
                '=' => Some(Kind::Equals),
                '@' => Some(Kind::At),
                '[' => Some(Kind::BracketL),
                ']' => Some(Kind::BracketR),
                '{' => Some(Kind::BraceL),
                '}' => Some(Kind::BraceR),
                '|' => Some(Kind::Pipe),
                _ => None,
            };
            if let Some(k) = punct {
                return Ok(self.tok(k, pos, pos + 1, None));
            }
            if c.is_ascii_digit() || c == '-' {
                return self.read_number(pos, c);
            }
            if is_name_start(c) {
                let mut p = pos + 1;
                while p < len && is_name_continue(body[p]) {
                    p += 1;
                }
                let v: String = body[pos..p].iter().collect();
                return Ok(self.tok(Kind::Name, pos, p, Some(v)));
            }
            if c == '.' {
                let next = self.at(pos + 1);
                if next == Some('.') {
                    if self.at(pos + 2) == Some('.') {
                        return Ok(self.tok(Kind::Spread, pos, pos + 3, None));
                    }
                    return self.err(pos, "Unexpected '..', did you mean '...'?");
                }
                if is_digit(next) {
                    let mut end = pos + 1;
                    while end < len && body[end].is_ascii_digit() {
                        end += 1;
                    }
                    let digits: String = body[pos + 1..end].iter().collect();
                    return self.err(
                        pos,
                        format!(
                            "Invalid number, expected digit before '.', did you mean '0.{digits}'?"
                        ),
                    );
                }
            }
            let message = if c == '\'' {
                "Unexpected single quote character ('), did you mean to use a double quote (\")?"
                    .to_owned()
            } else {
                format!("Unexpected character: {}.", self.print_code_point_at(pos))
            };
            return self.err(pos, message);
        }
        Ok(self.tok(Kind::Eof, len, len, None))
    }

    fn read_digits(&self, start: usize, first: Option<char>) -> PResult<usize> {
        if !is_digit(first) {
            return self.err(
                start,
                format!(
                    "Invalid number, expected digit but got: {}.",
                    self.print_code_point_at(start)
                ),
            );
        }
        let mut p = start + 1;
        while is_digit(self.at(p)) {
            p += 1;
        }
        Ok(p)
    }

    fn read_number(&self, start: usize, first: char) -> PResult<Token> {
        let mut pos = start;
        let mut c = Some(first);
        let mut is_float = false;
        if c == Some('-') {
            pos += 1;
            c = self.at(pos);
        }
        if c == Some('0') {
            pos += 1;
            c = self.at(pos);
            if is_digit(c) {
                return self.err(
                    pos,
                    format!(
                        "Invalid number, unexpected digit after 0: {}.",
                        self.print_code_point_at(pos)
                    ),
                );
            }
        } else {
            pos = self.read_digits(pos, c)?;
            c = self.at(pos);
        }
        if c == Some('.') {
            is_float = true;
            pos += 1;
            c = self.at(pos);
            pos = self.read_digits(pos, c)?;
            c = self.at(pos);
        }
        if matches!(c, Some('E' | 'e')) {
            is_float = true;
            pos += 1;
            c = self.at(pos);
            if matches!(c, Some('+' | '-')) {
                pos += 1;
                c = self.at(pos);
            }
            pos = self.read_digits(pos, c)?;
            c = self.at(pos);
        }
        if let Some(ch) = c
            && (ch == '.' || is_name_start(ch))
        {
            return self.err(
                pos,
                format!(
                    "Invalid number, expected digit but got: {}.",
                    self.print_code_point_at(pos)
                ),
            );
        }
        let v: String = self.body[start..pos].iter().collect();
        Ok(self.tok(
            if is_float { Kind::Float } else { Kind::Int },
            start,
            pos,
            Some(v),
        ))
    }

    fn read_string(&self, start: usize) -> PResult<Token> {
        let body = self.body;
        let len = body.len();
        let mut pos = start + 1;
        let mut value = String::new();
        while pos < len {
            let c = body[pos];
            if c == '"' {
                return Ok(self.tok(Kind::String, start, pos + 1, Some(value)));
            }
            if c == '\\' {
                let (ch, size) = if self.at(pos + 1) == Some('u') {
                    if self.at(pos + 2) == Some('{') {
                        self.escaped_unicode_variable(pos)?
                    } else {
                        self.escaped_unicode_fixed(pos)?
                    }
                } else {
                    self.escaped_character(pos)?
                };
                value.push(ch);
                pos += size;
                continue;
            }
            if c == '\r' || c == '\n' {
                break;
            }
            value.push(c);
            pos += 1;
        }
        self.err(pos, "Unterminated string.")
    }

    fn slice(&self, from: usize, to: usize) -> String {
        let to = to.min(self.body.len());
        self.body[from.min(to)..to].iter().collect()
    }

    fn escaped_unicode_variable(&self, position: usize) -> PResult<(char, usize)> {
        let mut point: i64 = 0;
        let mut size = 3;
        let max_size = 12.min(self.body.len() - position);
        while size < max_size {
            let c = self.at(position + size);
            size += 1;
            if c == Some('}') {
                if size < 5
                    || !((0..=0xd7ff).contains(&point) || (0xe000..=0x10ffff).contains(&point))
                {
                    break;
                }
                if let Some(ch) = char::from_u32(point as u32) {
                    return Ok((ch, size));
                }
                break;
            }
            let h = hex(c);
            point = if h < 0 { -1 } else { (point << 4) | h };
            if point < 0 {
                break;
            }
        }
        self.err(
            position,
            format!(
                "Invalid Unicode escape sequence: '{}'.",
                self.slice(position, position + size)
            ),
        )
    }

    fn hex16(&self, p: usize) -> i64 {
        let d = [
            hex(self.at(p)),
            hex(self.at(p + 1)),
            hex(self.at(p + 2)),
            hex(self.at(p + 3)),
        ];
        if self.body.len() < p + 4 {
            return -1;
        }
        // Python ORs the shifted values; a -1 anywhere makes it negative.
        (d[0] << 12) | (d[1] << 8) | (d[2] << 4) | d[3]
    }

    fn escaped_unicode_fixed(&self, position: usize) -> PResult<(char, usize)> {
        let code = self.hex16(position + 2);
        if ((0..=0xd7ff).contains(&code) || (0xe000..=0x10ffff).contains(&code))
            && let Some(ch) = char::from_u32(code as u32)
        {
            return Ok((ch, 6));
        }
        if (0xd800..=0xdbff).contains(&code)
            && self.at(position + 6) == Some('\\')
            && self.at(position + 7) == Some('u')
        {
            let trailing = self.hex16(position + 8);
            if (0xdc00..=0xdfff).contains(&trailing) {
                let cp = 0x10000 + ((code - 0xd800) << 10) + (trailing - 0xdc00);
                if let Some(ch) = char::from_u32(cp as u32) {
                    return Ok((ch, 12));
                }
            }
        }
        self.err(
            position,
            format!(
                "Invalid Unicode escape sequence: '{}'.",
                self.slice(position, position + 6)
            ),
        )
    }

    fn escaped_character(&self, position: usize) -> PResult<(char, usize)> {
        let v = match self.at(position + 1) {
            Some('"') => Some('"'),
            Some('/') => Some('/'),
            Some('\\') => Some('\\'),
            Some('b') => Some('\u{8}'),
            Some('f') => Some('\u{c}'),
            Some('n') => Some('\n'),
            Some('r') => Some('\r'),
            Some('t') => Some('\t'),
            _ => None,
        };
        match v {
            Some(c) => Ok((c, 2)),
            None => self.err(
                position,
                format!(
                    "Invalid character escape sequence: '{}'.",
                    self.slice(position, position + 2)
                ),
            ),
        }
    }

    fn read_block_string(&self, start: usize) -> PResult<Token> {
        let body = self.body;
        let len = body.len();
        let mut pos = start + 3;
        let mut chunk_start = pos;
        let mut current = String::new();
        let mut lines: Vec<String> = Vec::new();
        while pos < len {
            let c = body[pos];
            if c == '"' && self.at(pos + 1) == Some('"') && self.at(pos + 2) == Some('"') {
                current.push_str(&self.slice(chunk_start, pos));
                lines.push(current);
                let value = dedent_block_string_lines(&lines).join("\n");
                return Ok(self.tok(Kind::BlockString, start, pos + 3, Some(value)));
            }
            if c == '\\'
                && self.at(pos + 1) == Some('"')
                && self.at(pos + 2) == Some('"')
                && self.at(pos + 3) == Some('"')
            {
                current.push_str(&self.slice(chunk_start, pos));
                chunk_start = pos + 1;
                pos += 4;
                continue;
            }
            if c == '\r' || c == '\n' {
                current.push_str(&self.slice(chunk_start, pos));
                lines.push(std::mem::take(&mut current));
                if c == '\r' && self.at(pos + 1) == Some('\n') {
                    pos += 2;
                } else {
                    pos += 1;
                }
                chunk_start = pos;
                continue;
            }
            pos += 1;
        }
        self.err(pos, "Unterminated string.")
    }
}

/// `dedent_block_string_lines()`
fn dedent_block_string_lines(lines: &[String]) -> Vec<String> {
    let mut common = usize::MAX;
    let mut first_non_empty: Option<usize> = None;
    let mut last_non_empty: isize = -1;
    for (i, line) in lines.iter().enumerate() {
        let n = line.chars().count();
        let indent = line.chars().take_while(|c| *c == ' ' || *c == '\t').count();
        if indent == n {
            continue;
        }
        if first_non_empty.is_none() {
            first_non_empty = Some(i);
        }
        last_non_empty = i as isize;
        if i > 0 && indent < common {
            common = indent;
        }
    }
    let first = first_non_empty.unwrap_or(0);
    let mapped: Vec<String> = lines
        .iter()
        .enumerate()
        .map(|(i, l)| {
            if i > 0 {
                l.chars().skip(common).collect()
            } else {
                l.clone()
            }
        })
        .collect();
    let end = (last_non_empty + 1).max(0) as usize;
    if first >= end {
        return Vec::new();
    }
    mapped[first..end].to_vec()
}

/// How deeply selection sets, list and object values and list types may
/// nest. graphql-core's parser recurses a few Python frames per level and
/// ends in a `RecursionError` at Python's recursion limit (around 240
/// levels of selection sets in v4); this parser recurses too, so it stops
/// at a fixed depth before its stack could run out.
pub const MAX_NESTING: usize = 200;

/// The exception v4 ends with on a document nested too deeply.
pub const RECURSION_ERROR: &str = "RecursionError: maximum recursion depth exceeded";

/// Why [`parse_checked`] failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseFailure {
    /// A `GraphQLSyntaxError`.
    Syntax(SyntaxError),
    /// Nested deeper than [`MAX_NESTING`]: a `RecursionError`, which is
    /// not a GraphQL error and which ariadne does not catch.
    TooDeep,
}

/// `parse(source)`.
pub fn parse(body: &[char]) -> PResult<Document> {
    parse_checked(body).map_err(|e| match e {
        ParseFailure::Syntax(e) => e,
        ParseFailure::TooDeep => SyntaxError {
            pos: 0,
            description: RECURSION_ERROR.to_owned(),
        },
    })
}

/// `parse(source)`, telling a `RecursionError` from a syntax error.
pub fn parse_checked(body: &[char]) -> Result<Document, ParseFailure> {
    let mut p = Parser {
        lx: Lexer::new(body),
        depth: 0,
        too_deep: false,
    };
    match p.parse_document() {
        _ if p.too_deep => Err(ParseFailure::TooDeep),
        Ok(d) => Ok(d),
        Err(e) => Err(ParseFailure::Syntax(e)),
    }
}

struct Parser<'a> {
    lx: Lexer<'a>,
    depth: usize,
    too_deep: bool,
}

const DIRECTIVE_LOCATIONS: &[&str] = &[
    "QUERY",
    "MUTATION",
    "SUBSCRIPTION",
    "FIELD",
    "FRAGMENT_DEFINITION",
    "FRAGMENT_SPREAD",
    "INLINE_FRAGMENT",
    "VARIABLE_DEFINITION",
    "FRAGMENT_VARIABLE_DEFINITION",
    "SCHEMA",
    "SCALAR",
    "OBJECT",
    "FIELD_DEFINITION",
    "ARGUMENT_DEFINITION",
    "INTERFACE",
    "UNION",
    "ENUM",
    "ENUM_VALUE",
    "INPUT_OBJECT",
    "INPUT_FIELD_DEFINITION",
    "DIRECTIVE_DEFINITION",
];

impl Parser<'_> {
    fn peek(&self, k: Kind) -> bool {
        self.lx.token.kind == k
    }

    fn pos(&self) -> usize {
        self.lx.token.start
    }

    /// Run `f` one nesting level deeper, or fail past [`MAX_NESTING`].
    fn nested<T>(&mut self, f: impl FnOnce(&mut Self) -> PResult<T>) -> PResult<T> {
        if self.depth >= MAX_NESTING {
            self.too_deep = true;
            return Err(SyntaxError {
                pos: self.pos(),
                description: RECURSION_ERROR.to_owned(),
            });
        }
        self.depth += 1;
        let r = f(self);
        self.depth -= 1;
        r
    }

    fn unexpected<T>(&self, at: Option<&Token>) -> PResult<T> {
        let t = at.unwrap_or(&self.lx.token);
        Err(SyntaxError {
            pos: t.start,
            description: format!("Unexpected {}.", t.desc()),
        })
    }

    fn expect(&mut self, k: Kind) -> PResult<Token> {
        let t = self.lx.token.clone();
        if t.kind == k {
            self.lx.advance()?;
            return Ok(t);
        }
        Err(SyntaxError {
            pos: t.start,
            description: format!("Expected {}, found {}.", k.desc(), t.desc()),
        })
    }

    fn expect_optional(&mut self, k: Kind) -> PResult<bool> {
        if self.lx.token.kind == k {
            self.lx.advance()?;
            return Ok(true);
        }
        Ok(false)
    }

    fn expect_keyword(&mut self, value: &str) -> PResult<()> {
        let t = &self.lx.token;
        if t.kind == Kind::Name && t.value.as_deref() == Some(value) {
            self.lx.advance()
        } else {
            Err(SyntaxError {
                pos: t.start,
                description: format!("Expected '{value}', found {}.", t.desc()),
            })
        }
    }

    fn expect_optional_keyword(&mut self, value: &str) -> PResult<bool> {
        let t = &self.lx.token;
        if t.kind == Kind::Name && t.value.as_deref() == Some(value) {
            self.lx.advance()?;
            return Ok(true);
        }
        Ok(false)
    }

    fn parse_name(&mut self) -> PResult<Name> {
        let t = self.expect(Kind::Name)?;
        Ok(Name {
            pos: t.start,
            value: t.value.unwrap_or_default(),
        })
    }

    fn many<T>(
        &mut self,
        open: Kind,
        mut f: impl FnMut(&mut Self) -> PResult<T>,
        close: Kind,
    ) -> PResult<Vec<T>> {
        self.expect(open)?;
        let mut out = vec![f(self)?];
        while !self.expect_optional(close)? {
            out.push(f(self)?);
        }
        Ok(out)
    }

    fn optional_many<T>(
        &mut self,
        open: Kind,
        mut f: impl FnMut(&mut Self) -> PResult<T>,
        close: Kind,
    ) -> PResult<Vec<T>> {
        if self.expect_optional(open)? {
            let mut out = vec![f(self)?];
            while !self.expect_optional(close)? {
                out.push(f(self)?);
            }
            return Ok(out);
        }
        Ok(Vec::new())
    }

    fn any<T>(
        &mut self,
        open: Kind,
        mut f: impl FnMut(&mut Self) -> PResult<T>,
        close: Kind,
    ) -> PResult<Vec<T>> {
        self.expect(open)?;
        let mut out = Vec::new();
        while !self.expect_optional(close)? {
            out.push(f(self)?);
        }
        Ok(out)
    }

    fn delimited_many<T>(
        &mut self,
        delim: Kind,
        mut f: impl FnMut(&mut Self) -> PResult<T>,
    ) -> PResult<Vec<T>> {
        self.expect_optional(delim)?;
        let mut out = Vec::new();
        loop {
            out.push(f(self)?);
            if !self.expect_optional(delim)? {
                break;
            }
        }
        Ok(out)
    }

    fn parse_document(&mut self) -> PResult<Document> {
        let definitions = self.many(Kind::Sof, Self::parse_definition, Kind::Eof)?;
        Ok(Document { definitions })
    }

    fn peek_description(&self) -> bool {
        self.peek(Kind::String) || self.peek(Kind::BlockString)
    }

    fn parse_description(&mut self) -> PResult<Option<String>> {
        if self.peek_description() {
            let t = self.lx.token.clone();
            self.lx.advance()?;
            return Ok(Some(t.value.unwrap_or_default()));
        }
        Ok(None)
    }

    fn parse_definition(&mut self) -> PResult<Definition> {
        if self.peek(Kind::BraceL) {
            return Ok(Definition::Operation(self.parse_operation_definition()?));
        }
        let has_description = self.peek_description();
        let keyword = if has_description {
            self.lx.lookahead()?
        } else {
            self.lx.token.clone()
        };
        if has_description && keyword.kind == Kind::BraceL {
            return Err(SyntaxError {
                pos: self.lx.token.start,
                description:
                    "Unexpected description, descriptions are not supported on shorthand queries."
                        .into(),
            });
        }
        if keyword.kind == Kind::Name {
            let name = keyword.value.clone().unwrap_or_default();
            let ts = match name.as_str() {
                "schema" => Some(TypeSystemKind::SchemaDefinition),
                "scalar" => Some(TypeSystemKind::ScalarTypeDefinition),
                "type" => Some(TypeSystemKind::ObjectTypeDefinition),
                "interface" => Some(TypeSystemKind::InterfaceTypeDefinition),
                "union" => Some(TypeSystemKind::UnionTypeDefinition),
                "enum" => Some(TypeSystemKind::EnumTypeDefinition),
                "input" => Some(TypeSystemKind::InputObjectTypeDefinition),
                "directive" => Some(TypeSystemKind::DirectiveDefinition),
                _ => None,
            };
            if let Some(k) = ts {
                return Ok(Definition::TypeSystem(self.parse_type_system(k)?));
            }
            match name.as_str() {
                "query" | "mutation" | "subscription" => {
                    return Ok(Definition::Operation(self.parse_operation_definition()?));
                }
                "fragment" => {
                    return Ok(Definition::Fragment(self.parse_fragment_definition()?));
                }
                _ => {}
            }
            if has_description {
                return Err(SyntaxError {
                    pos: self.lx.token.start,
                    description:
                        "Unexpected description, only GraphQL definitions support descriptions."
                            .into(),
                });
            }
            if name == "extend" {
                return Ok(Definition::TypeSystem(self.parse_type_system_extension()?));
            }
        }
        self.unexpected(Some(&keyword))
    }

    fn parse_operation_definition(&mut self) -> PResult<OperationDefinition> {
        let start = self.pos();
        if self.peek(Kind::BraceL) {
            return Ok(OperationDefinition {
                pos: start,
                operation: OperationType::Query,
                name: None,
                variable_definitions: Vec::new(),
                directives: Vec::new(),
                selection_set: self.parse_selection_set()?,
            });
        }
        self.parse_description()?;
        let operation = self.parse_operation_type()?;
        let name = if self.peek(Kind::Name) {
            Some(self.parse_name()?)
        } else {
            None
        };
        let variable_definitions =
            self.optional_many(Kind::ParenL, Self::parse_variable_definition, Kind::ParenR)?;
        let directives = self.parse_directives(false)?;
        let selection_set = self.parse_selection_set()?;
        Ok(OperationDefinition {
            pos: start,
            operation,
            name,
            variable_definitions,
            directives,
            selection_set,
        })
    }

    fn parse_operation_type(&mut self) -> PResult<OperationType> {
        let t = self.expect(Kind::Name)?;
        match t.value.as_deref() {
            Some("query") => Ok(OperationType::Query),
            Some("mutation") => Ok(OperationType::Mutation),
            Some("subscription") => Ok(OperationType::Subscription),
            _ => self.unexpected(Some(&t)),
        }
    }

    fn parse_variable_definition(&mut self) -> PResult<VariableDefinition> {
        let start = self.pos();
        self.parse_description()?;
        let variable = self.parse_variable()?;
        self.expect(Kind::Colon)?;
        let type_ = self.parse_type_reference()?;
        let default_value = if self.expect_optional(Kind::Equals)? {
            Some(self.parse_value_literal(true)?)
        } else {
            None
        };
        let directives = self.parse_directives(true)?;
        Ok(VariableDefinition {
            pos: start,
            variable,
            type_,
            default_value,
            directives,
        })
    }

    fn parse_variable(&mut self) -> PResult<Variable> {
        let start = self.pos();
        self.expect(Kind::Dollar)?;
        Ok(Variable {
            pos: start,
            name: self.parse_name()?,
        })
    }

    fn parse_selection_set(&mut self) -> PResult<SelectionSet> {
        let start = self.pos();
        let selections =
            self.nested(|p| p.many(Kind::BraceL, Self::parse_selection, Kind::BraceR))?;
        Ok(SelectionSet {
            pos: start,
            selections,
        })
    }

    fn parse_selection(&mut self) -> PResult<Selection> {
        if self.peek(Kind::Spread) {
            self.parse_fragment()
        } else {
            Ok(Selection::Field(self.parse_field()?))
        }
    }

    fn parse_field(&mut self) -> PResult<Field> {
        let start = self.pos();
        let name_or_alias = self.parse_name()?;
        let (alias, name) = if self.expect_optional(Kind::Colon)? {
            (Some(name_or_alias), self.parse_name()?)
        } else {
            (None, name_or_alias)
        };
        let arguments = self.parse_arguments(false)?;
        let directives = self.parse_directives(false)?;
        let selection_set = if self.peek(Kind::BraceL) {
            Some(self.parse_selection_set()?)
        } else {
            None
        };
        Ok(Field {
            pos: start,
            alias,
            name,
            arguments,
            directives,
            selection_set,
        })
    }

    fn parse_arguments(&mut self, is_const: bool) -> PResult<Vec<Argument>> {
        self.optional_many(Kind::ParenL, |p| p.parse_argument(is_const), Kind::ParenR)
    }

    fn parse_argument(&mut self, is_const: bool) -> PResult<Argument> {
        let start = self.pos();
        let name = self.parse_name()?;
        self.expect(Kind::Colon)?;
        let value = self.parse_value_literal(is_const)?;
        Ok(Argument {
            pos: start,
            name,
            value,
        })
    }

    fn parse_fragment(&mut self) -> PResult<Selection> {
        let start = self.pos();
        self.expect(Kind::Spread)?;
        let has_type_condition = self.expect_optional_keyword("on")?;
        if !has_type_condition && self.peek(Kind::Name) {
            let name = self.parse_fragment_name()?;
            let directives = self.parse_directives(false)?;
            return Ok(Selection::FragmentSpread(FragmentSpread {
                pos: start,
                name,
                directives,
            }));
        }
        let type_condition = if has_type_condition {
            Some(self.parse_named_type()?)
        } else {
            None
        };
        let directives = self.parse_directives(false)?;
        let selection_set = self.parse_selection_set()?;
        Ok(Selection::InlineFragment(InlineFragment {
            pos: start,
            type_condition,
            directives,
            selection_set,
        }))
    }

    fn parse_fragment_definition(&mut self) -> PResult<FragmentDefinition> {
        let start = self.pos();
        self.parse_description()?;
        self.expect_keyword("fragment")?;
        let name = self.parse_fragment_name()?;
        self.expect_keyword("on")?;
        let type_condition = self.parse_named_type()?;
        let directives = self.parse_directives(false)?;
        let selection_set = self.parse_selection_set()?;
        Ok(FragmentDefinition {
            pos: start,
            name,
            type_condition,
            directives,
            selection_set,
        })
    }

    fn parse_fragment_name(&mut self) -> PResult<Name> {
        if self.lx.token.value.as_deref() == Some("on") {
            return self.unexpected(None);
        }
        self.parse_name()
    }

    fn parse_value_literal(&mut self, is_const: bool) -> PResult<ValueNode> {
        let t = self.lx.token.clone();
        match t.kind {
            Kind::BracketL => {
                let items = self.nested(|p| {
                    p.any(
                        Kind::BracketL,
                        |p| p.parse_value_literal(is_const),
                        Kind::BracketR,
                    )
                })?;
                Ok(ValueNode::List(t.start, items))
            }
            Kind::BraceL => {
                let fields = self.nested(|p| {
                    p.any(
                        Kind::BraceL,
                        |p| {
                            let start = p.pos();
                            let name = p.parse_name()?;
                            p.expect(Kind::Colon)?;
                            let value = p.parse_value_literal(is_const)?;
                            Ok(ObjectField {
                                pos: start,
                                name,
                                value,
                            })
                        },
                        Kind::BraceR,
                    )
                })?;
                Ok(ValueNode::Object(t.start, fields))
            }
            Kind::Int => {
                self.lx.advance()?;
                Ok(ValueNode::Int(t.start, t.value.unwrap_or_default()))
            }
            Kind::Float => {
                self.lx.advance()?;
                Ok(ValueNode::Float(t.start, t.value.unwrap_or_default()))
            }
            Kind::String | Kind::BlockString => {
                self.lx.advance()?;
                Ok(ValueNode::String(
                    t.start,
                    t.value.unwrap_or_default(),
                    t.kind == Kind::BlockString,
                ))
            }
            Kind::Name => {
                self.lx.advance()?;
                let v = t.value.unwrap_or_default();
                Ok(match v.as_str() {
                    "true" => ValueNode::Boolean(t.start, true),
                    "false" => ValueNode::Boolean(t.start, false),
                    "null" => ValueNode::Null(t.start),
                    _ => ValueNode::Enum(t.start, v),
                })
            }
            Kind::Dollar => {
                if is_const {
                    let var_tok = self.expect(Kind::Dollar)?;
                    let tok = self.lx.token.clone();
                    if tok.kind == Kind::Name {
                        return Err(SyntaxError {
                            pos: var_tok.start,
                            description: format!(
                                "Unexpected variable '${}' in constant value.",
                                tok.value.unwrap_or_default()
                            ),
                        });
                    }
                    return self.unexpected(Some(&var_tok));
                }
                Ok(ValueNode::Variable(self.parse_variable()?))
            }
            _ => self.unexpected(None),
        }
    }

    fn parse_directives(&mut self, is_const: bool) -> PResult<Vec<Directive>> {
        let mut out = Vec::new();
        while self.peek(Kind::At) {
            let start = self.pos();
            self.expect(Kind::At)?;
            let name = self.parse_name()?;
            let arguments = self.parse_arguments(is_const)?;
            out.push(Directive {
                pos: start,
                name,
                arguments,
            });
        }
        Ok(out)
    }

    fn parse_type_reference(&mut self) -> PResult<Type> {
        let start = self.pos();
        let t = if self.expect_optional(Kind::BracketL)? {
            let inner = self.nested(Self::parse_type_reference)?;
            self.expect(Kind::BracketR)?;
            Type::List(start, Box::new(inner))
        } else {
            Type::Named(self.parse_named_type()?)
        };
        if self.expect_optional(Kind::Bang)? {
            return Ok(Type::NonNull(start, Box::new(t)));
        }
        Ok(t)
    }

    fn parse_named_type(&mut self) -> PResult<NamedType> {
        let start = self.pos();
        Ok(NamedType {
            pos: start,
            name: self.parse_name()?,
        })
    }

    // ---- type system ----

    fn blank(&self, pos: usize, kind: TypeSystemKind) -> TypeSystemDefinition {
        TypeSystemDefinition {
            pos,
            kind,
            description: None,
            name: None,
            directives: Vec::new(),
            fields: Vec::new(),
            interfaces: Vec::new(),
            types: Vec::new(),
            values: Vec::new(),
            arguments: Vec::new(),
            locations: Vec::new(),
            repeatable: false,
            operation_types: Vec::new(),
        }
    }

    fn parse_type_system(&mut self, kind: TypeSystemKind) -> PResult<TypeSystemDefinition> {
        let start = self.pos();
        let mut d = self.blank(start, kind);
        d.description = self.parse_description()?;
        match kind {
            TypeSystemKind::SchemaDefinition => {
                self.expect_keyword("schema")?;
                d.directives = self.parse_directives(true)?;
                d.operation_types = self.many(
                    Kind::BraceL,
                    Self::parse_operation_type_definition,
                    Kind::BraceR,
                )?;
            }
            TypeSystemKind::ScalarTypeDefinition => {
                self.expect_keyword("scalar")?;
                d.name = Some(self.parse_name()?);
                d.directives = self.parse_directives(true)?;
            }
            TypeSystemKind::ObjectTypeDefinition | TypeSystemKind::InterfaceTypeDefinition => {
                self.expect_keyword(if kind == TypeSystemKind::ObjectTypeDefinition {
                    "type"
                } else {
                    "interface"
                })?;
                d.name = Some(self.parse_name()?);
                d.interfaces = self.parse_implements()?;
                d.directives = self.parse_directives(true)?;
                d.fields =
                    self.optional_many(Kind::BraceL, Self::parse_field_definition, Kind::BraceR)?;
            }
            TypeSystemKind::UnionTypeDefinition => {
                self.expect_keyword("union")?;
                d.name = Some(self.parse_name()?);
                d.directives = self.parse_directives(true)?;
                d.types = self.parse_union_members()?;
            }
            TypeSystemKind::EnumTypeDefinition => {
                self.expect_keyword("enum")?;
                d.name = Some(self.parse_name()?);
                d.directives = self.parse_directives(true)?;
                d.values =
                    self.optional_many(Kind::BraceL, Self::parse_enum_value_def, Kind::BraceR)?;
            }
            TypeSystemKind::InputObjectTypeDefinition => {
                self.expect_keyword("input")?;
                d.name = Some(self.parse_name()?);
                d.directives = self.parse_directives(true)?;
                d.fields = self.parse_input_fields()?;
            }
            TypeSystemKind::DirectiveDefinition => {
                self.expect_keyword("directive")?;
                self.expect(Kind::At)?;
                d.name = Some(self.parse_name()?);
                d.arguments =
                    self.optional_many(Kind::ParenL, Self::parse_input_value_def, Kind::ParenR)?;
                d.directives = self.parse_directives(true)?;
                d.repeatable = self.expect_optional_keyword("repeatable")?;
                self.expect_keyword("on")?;
                d.locations = self.delimited_many(Kind::Pipe, Self::parse_directive_location)?;
            }
            _ => return self.unexpected(None),
        }
        Ok(d)
    }

    fn parse_input_fields(&mut self) -> PResult<Vec<FieldDefinition>> {
        let v = self.optional_many(Kind::BraceL, Self::parse_input_value_def, Kind::BraceR)?;
        Ok(v.into_iter()
            .map(|i| FieldDefinition {
                pos: i.pos,
                description: i.description,
                name: i.name,
                arguments: Vec::new(),
                type_: i.type_,
                default_value: i.default_value,
                directives: i.directives,
            })
            .collect())
    }

    fn parse_directive_location(&mut self) -> PResult<Name> {
        let start = self.lx.token.clone();
        let name = self.parse_name()?;
        if DIRECTIVE_LOCATIONS.contains(&name.value.as_str()) {
            return Ok(name);
        }
        self.unexpected(Some(&start))
    }

    fn parse_operation_type_definition(&mut self) -> PResult<(OperationType, NamedType)> {
        let op = self.parse_operation_type()?;
        self.expect(Kind::Colon)?;
        let t = self.parse_named_type()?;
        Ok((op, t))
    }

    fn parse_implements(&mut self) -> PResult<Vec<NamedType>> {
        if self.expect_optional_keyword("implements")? {
            return self.delimited_many(Kind::Amp, Self::parse_named_type);
        }
        Ok(Vec::new())
    }

    fn parse_union_members(&mut self) -> PResult<Vec<NamedType>> {
        if self.expect_optional(Kind::Equals)? {
            return self.delimited_many(Kind::Pipe, Self::parse_named_type);
        }
        Ok(Vec::new())
    }

    fn parse_field_definition(&mut self) -> PResult<FieldDefinition> {
        let start = self.pos();
        let description = self.parse_description()?;
        let name = self.parse_name()?;
        let arguments =
            self.optional_many(Kind::ParenL, Self::parse_input_value_def, Kind::ParenR)?;
        self.expect(Kind::Colon)?;
        let type_ = self.parse_type_reference()?;
        let directives = self.parse_directives(true)?;
        Ok(FieldDefinition {
            pos: start,
            description,
            name,
            arguments,
            type_,
            default_value: None,
            directives,
        })
    }

    fn parse_input_value_def(&mut self) -> PResult<InputValueDefinition> {
        let start = self.pos();
        let description = self.parse_description()?;
        let name = self.parse_name()?;
        self.expect(Kind::Colon)?;
        let type_ = self.parse_type_reference()?;
        let default_value = if self.expect_optional(Kind::Equals)? {
            Some(self.parse_value_literal(true)?)
        } else {
            None
        };
        let directives = self.parse_directives(true)?;
        Ok(InputValueDefinition {
            pos: start,
            description,
            name,
            type_,
            default_value,
            directives,
        })
    }

    fn parse_enum_value_def(&mut self) -> PResult<EnumValueDefinition> {
        let start = self.pos();
        let description = self.parse_description()?;
        if matches!(
            self.lx.token.value.as_deref(),
            Some("true" | "false" | "null")
        ) {
            return Err(SyntaxError {
                pos: self.lx.token.start,
                description: format!(
                    "{} is reserved and cannot be used for an enum value.",
                    self.lx.token.desc()
                ),
            });
        }
        let name = self.parse_name()?;
        let directives = self.parse_directives(true)?;
        Ok(EnumValueDefinition {
            pos: start,
            description,
            name,
            directives,
        })
    }

    fn parse_type_system_extension(&mut self) -> PResult<TypeSystemDefinition> {
        let keyword = self.lx.lookahead()?;
        if keyword.kind == Kind::Name {
            let kind = match keyword.value.as_deref() {
                Some("schema") => Some(TypeSystemKind::SchemaExtension),
                Some("scalar") => Some(TypeSystemKind::ScalarTypeExtension),
                Some("type") => Some(TypeSystemKind::ObjectTypeExtension),
                Some("interface") => Some(TypeSystemKind::InterfaceTypeExtension),
                Some("union") => Some(TypeSystemKind::UnionTypeExtension),
                Some("enum") => Some(TypeSystemKind::EnumTypeExtension),
                Some("input") => Some(TypeSystemKind::InputObjectTypeExtension),
                Some("directive") => Some(TypeSystemKind::DirectiveExtension),
                _ => None,
            };
            if let Some(kind) = kind {
                return self.parse_extension(kind, keyword.value.unwrap_or_default());
            }
        }
        self.unexpected(Some(&keyword))
    }

    fn parse_extension(
        &mut self,
        kind: TypeSystemKind,
        kw: String,
    ) -> PResult<TypeSystemDefinition> {
        let start = self.pos();
        let mut d = self.blank(start, kind);
        self.expect_keyword("extend")?;
        self.expect_keyword(&kw)?;
        let ok = match kind {
            TypeSystemKind::SchemaExtension => {
                d.directives = self.parse_directives(true)?;
                d.operation_types = self.optional_many(
                    Kind::BraceL,
                    Self::parse_operation_type_definition,
                    Kind::BraceR,
                )?;
                !d.directives.is_empty() || !d.operation_types.is_empty()
            }
            TypeSystemKind::ScalarTypeExtension => {
                d.name = Some(self.parse_name()?);
                d.directives = self.parse_directives(true)?;
                !d.directives.is_empty()
            }
            TypeSystemKind::ObjectTypeExtension | TypeSystemKind::InterfaceTypeExtension => {
                d.name = Some(self.parse_name()?);
                d.interfaces = self.parse_implements()?;
                d.directives = self.parse_directives(true)?;
                d.fields =
                    self.optional_many(Kind::BraceL, Self::parse_field_definition, Kind::BraceR)?;
                !d.interfaces.is_empty() || !d.directives.is_empty() || !d.fields.is_empty()
            }
            TypeSystemKind::UnionTypeExtension => {
                d.name = Some(self.parse_name()?);
                d.directives = self.parse_directives(true)?;
                d.types = self.parse_union_members()?;
                !d.directives.is_empty() || !d.types.is_empty()
            }
            TypeSystemKind::EnumTypeExtension => {
                d.name = Some(self.parse_name()?);
                d.directives = self.parse_directives(true)?;
                d.values =
                    self.optional_many(Kind::BraceL, Self::parse_enum_value_def, Kind::BraceR)?;
                !d.directives.is_empty() || !d.values.is_empty()
            }
            TypeSystemKind::InputObjectTypeExtension => {
                d.name = Some(self.parse_name()?);
                d.directives = self.parse_directives(true)?;
                d.fields = self.parse_input_fields()?;
                !d.directives.is_empty() || !d.fields.is_empty()
            }
            TypeSystemKind::DirectiveExtension => {
                self.expect(Kind::At)?;
                d.name = Some(self.parse_name()?);
                d.directives = self.parse_directives(true)?;
                !d.directives.is_empty()
            }
            _ => false,
        };
        if !ok {
            return self.unexpected(None);
        }
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(src: &str) -> (String, (usize, usize)) {
        let chars: Vec<char> = src.chars().collect();
        match parse(&chars) {
            Ok(_) => panic!("parsed: {src}"),
            Err(e) => (e.description, location(&chars, e.pos)),
        }
    }

    #[test]
    fn syntax_errors_like_graphql_core() {
        assert_eq!(err("{"), ("Expected Name, found <EOF>.".into(), (1, 2)));
        assert_eq!(err("{ a(b: ) }"), ("Unexpected ')'.".into(), (1, 8)));
        assert_eq!(
            err("query { a"),
            ("Expected Name, found <EOF>.".into(), (1, 10))
        );
        assert_eq!(err("foo"), ("Unexpected Name 'foo'.".into(), (1, 1)));
        assert_eq!(
            err("{ a(x: \"abc) }"),
            ("Unterminated string.".into(), (1, 15))
        );
        assert_eq!(
            err("{ a(x: 'abc') }"),
            (
                "Unexpected single quote character ('), did you mean to use a double quote (\")?"
                    .into(),
                (1, 8)
            )
        );
        assert_eq!(
            err("{ a(x: 01) }"),
            (
                "Invalid number, unexpected digit after 0: '1'.".into(),
                (1, 9)
            )
        );
        assert_eq!(err("\n\n?"), ("Unexpected character: '?'.".into(), (2, 1)));
        assert_eq!(err("{ a }\n}"), ("Unexpected '}'.".into(), (1, 6)));
    }

    #[test]
    fn parses_queries() {
        let chars: Vec<char> = "query Q($a: [String!]! = [\"x\"]) @dir { x: f(a: $a, b: {c: 1.5}) { ...F ... on T { g } } } fragment F on T { h }".chars().collect();
        let d = parse(&chars).expect("parse");
        assert_eq!(d.definitions.len(), 2);
    }

    #[test]
    fn block_strings_dedent() {
        let chars: Vec<char> = "{ a(x: \"\"\"\n    hello\n      world\n  \"\"\") }"
            .chars()
            .collect();
        let d = parse(&chars).expect("parse");
        let Definition::Operation(op) = &d.definitions[0] else {
            panic!()
        };
        let Selection::Field(f) = &op.selection_set.selections[0] else {
            panic!()
        };
        let ValueNode::String(_, s, true) = &f.arguments[0].value else {
            panic!()
        };
        assert_eq!(s, "hello\n  world");
    }
}
