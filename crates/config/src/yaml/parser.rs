//! `yaml/parser.py`.

use std::collections::HashMap;

use super::scanner::{DirectiveValue, Scanner, Token, TokenKind};
use super::{Error, Mark, MarkedError};
use crate::python::str_repr;

#[derive(Clone, Debug)]
pub(crate) enum EventKind {
    StreamStart,
    StreamEnd,
    DocumentStart,
    DocumentEnd,
    Alias(String),
    Scalar {
        anchor: Option<String>,
        tag: Option<String>,
        implicit: (bool, bool),
        value: String,
    },
    SequenceStart {
        anchor: Option<String>,
        tag: Option<String>,
    },
    SequenceEnd,
    MappingStart {
        anchor: Option<String>,
        tag: Option<String>,
    },
    MappingEnd,
}

#[derive(Clone, Debug)]
pub(crate) struct Event {
    pub(crate) kind: EventKind,
    pub(crate) start_mark: Mark,
    /// Unused by the composer, as in PyYAML, but kept so the parser reads
    /// like `parser.py`.
    #[allow(dead_code)]
    pub(crate) end_mark: Mark,
}

#[derive(Clone, Copy, Debug)]
enum State {
    StreamStart,
    ImplicitDocumentStart,
    DocumentStart,
    DocumentEnd,
    DocumentContent,
    BlockNode,
    BlockSequenceFirstEntry,
    BlockSequenceEntry,
    IndentlessSequenceEntry,
    BlockMappingFirstKey,
    BlockMappingKey,
    BlockMappingValue,
    FlowSequenceFirstEntry,
    FlowSequenceEntry,
    FlowSequenceEntryMappingKey,
    FlowSequenceEntryMappingValue,
    FlowSequenceEntryMappingEnd,
    FlowMappingFirstKey,
    FlowMappingKey,
    FlowMappingValue,
    FlowMappingEmptyValue,
}

type Result<T> = std::result::Result<T, Error>;

fn parser_error(
    context: Option<&str>,
    context_mark: Option<Mark>,
    problem: String,
    problem_mark: Mark,
) -> Error {
    Error::Marked(MarkedError::new(
        context,
        context_mark,
        problem,
        Some(problem_mark),
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Directive,
    DocumentStart,
    DocumentEnd,
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
    Alias,
    Anchor,
    Tag,
    Scalar,
    Other,
}

fn kind_of(t: &Token) -> Kind {
    match t.kind {
        TokenKind::Directive { .. } => Kind::Directive,
        TokenKind::DocumentStart => Kind::DocumentStart,
        TokenKind::DocumentEnd => Kind::DocumentEnd,
        TokenKind::StreamEnd => Kind::StreamEnd,
        TokenKind::BlockSequenceStart => Kind::BlockSequenceStart,
        TokenKind::BlockMappingStart => Kind::BlockMappingStart,
        TokenKind::BlockEnd => Kind::BlockEnd,
        TokenKind::FlowSequenceStart => Kind::FlowSequenceStart,
        TokenKind::FlowMappingStart => Kind::FlowMappingStart,
        TokenKind::FlowSequenceEnd => Kind::FlowSequenceEnd,
        TokenKind::FlowMappingEnd => Kind::FlowMappingEnd,
        TokenKind::Key => Kind::Key,
        TokenKind::Value => Kind::Value,
        TokenKind::BlockEntry => Kind::BlockEntry,
        TokenKind::FlowEntry => Kind::FlowEntry,
        TokenKind::Alias(_) => Kind::Alias,
        TokenKind::Anchor(_) => Kind::Anchor,
        TokenKind::Tag(..) => Kind::Tag,
        TokenKind::Scalar { .. } => Kind::Scalar,
        TokenKind::StreamStart => Kind::Other,
    }
}

pub(crate) struct Parser {
    pub(crate) scanner: Scanner,
    current_event: Option<Event>,
    tag_handles: HashMap<String, String>,
    states: Vec<State>,
    marks: Vec<Mark>,
    state: Option<State>,
}

fn default_tags() -> HashMap<String, String> {
    HashMap::from([
        ("!".to_owned(), "!".to_owned()),
        ("!!".to_owned(), "tag:yaml.org,2002:".to_owned()),
    ])
}

impl Parser {
    pub(crate) fn new(scanner: Scanner) -> Self {
        Parser {
            scanner,
            current_event: None,
            tag_handles: HashMap::new(),
            states: Vec::new(),
            marks: Vec::new(),
            state: Some(State::StreamStart),
        }
    }

    pub(crate) fn peek_event(&mut self) -> Result<Option<&Event>> {
        if self.current_event.is_none()
            && let Some(state) = self.state
        {
            self.current_event = Some(self.run(state)?);
        }
        Ok(self.current_event.as_ref())
    }

    pub(crate) fn get_event(&mut self) -> Result<Option<Event>> {
        self.peek_event()?;
        Ok(self.current_event.take())
    }

    // Token helpers.

    fn check(&mut self, kinds: &[Kind]) -> Result<bool> {
        Ok(self
            .scanner
            .peek_token()?
            .is_some_and(|t| kinds.contains(&kind_of(t))))
    }

    fn peek_token(&mut self) -> Result<Token> {
        let token = self.scanner.peek_token()?.cloned();
        // The scanner always ends with a stream end token, which the parser
        // never consumes before it stops asking.
        Ok(token.unwrap_or(Token {
            kind: TokenKind::StreamEnd,
            start_mark: self.scanner.reader.get_mark(),
            end_mark: self.scanner.reader.get_mark(),
        }))
    }

    fn get_token(&mut self) -> Result<Token> {
        let token = self.scanner.get_token()?;
        Ok(token.unwrap_or(Token {
            kind: TokenKind::StreamEnd,
            start_mark: self.scanner.reader.get_mark(),
            end_mark: self.scanner.reader.get_mark(),
        }))
    }

    fn pop_state(&mut self) -> Option<State> {
        self.states.pop()
    }

    fn run(&mut self, state: State) -> Result<Event> {
        match state {
            State::StreamStart => self.parse_stream_start(),
            State::ImplicitDocumentStart => self.parse_implicit_document_start(),
            State::DocumentStart => self.parse_document_start(),
            State::DocumentEnd => self.parse_document_end(),
            State::DocumentContent => self.parse_document_content(),
            State::BlockNode => self.parse_node(true, false),
            State::BlockSequenceFirstEntry => self.parse_block_sequence_first_entry(),
            State::BlockSequenceEntry => self.parse_block_sequence_entry(),
            State::IndentlessSequenceEntry => self.parse_indentless_sequence_entry(),
            State::BlockMappingFirstKey => self.parse_block_mapping_first_key(),
            State::BlockMappingKey => self.parse_block_mapping_key(),
            State::BlockMappingValue => self.parse_block_mapping_value(),
            State::FlowSequenceFirstEntry => self.parse_flow_sequence_entry(true, true),
            State::FlowSequenceEntry => self.parse_flow_sequence_entry(false, false),
            State::FlowSequenceEntryMappingKey => self.parse_flow_sequence_entry_mapping_key(),
            State::FlowSequenceEntryMappingValue => self.parse_flow_sequence_entry_mapping_value(),
            State::FlowSequenceEntryMappingEnd => self.parse_flow_sequence_entry_mapping_end(),
            State::FlowMappingFirstKey => self.parse_flow_mapping_key(true, true),
            State::FlowMappingKey => self.parse_flow_mapping_key(false, false),
            State::FlowMappingValue => self.parse_flow_mapping_value(),
            State::FlowMappingEmptyValue => self.parse_flow_mapping_empty_value(),
        }
    }

    fn event(kind: EventKind, start_mark: Mark, end_mark: Mark) -> Event {
        Event {
            kind,
            start_mark,
            end_mark,
        }
    }

    fn parse_stream_start(&mut self) -> Result<Event> {
        let token = self.get_token()?;
        self.state = Some(State::ImplicitDocumentStart);
        Ok(Self::event(
            EventKind::StreamStart,
            token.start_mark,
            token.end_mark,
        ))
    }

    fn parse_implicit_document_start(&mut self) -> Result<Event> {
        if !self.check(&[Kind::Directive, Kind::DocumentStart, Kind::StreamEnd])? {
            self.tag_handles = default_tags();
            let token = self.peek_token()?;
            self.states.push(State::DocumentEnd);
            self.state = Some(State::BlockNode);
            Ok(Self::event(
                EventKind::DocumentStart,
                token.start_mark,
                token.start_mark,
            ))
        } else {
            self.parse_document_start()
        }
    }

    fn parse_document_start(&mut self) -> Result<Event> {
        while self.check(&[Kind::DocumentEnd])? {
            self.get_token()?;
        }
        if !self.check(&[Kind::StreamEnd])? {
            let token = self.peek_token()?;
            let start_mark = token.start_mark;
            self.process_directives()?;
            if !self.check(&[Kind::DocumentStart])? {
                let t = self.peek_token()?;
                return Err(parser_error(
                    None,
                    None,
                    format!(
                        "expected '<document start>', but found {}",
                        str_repr(t.kind.id())
                    ),
                    t.start_mark,
                ));
            }
            let token = self.get_token()?;
            self.states.push(State::DocumentEnd);
            self.state = Some(State::DocumentContent);
            Ok(Self::event(
                EventKind::DocumentStart,
                start_mark,
                token.end_mark,
            ))
        } else {
            let token = self.get_token()?;
            self.state = None;
            Ok(Self::event(
                EventKind::StreamEnd,
                token.start_mark,
                token.end_mark,
            ))
        }
    }

    fn parse_document_end(&mut self) -> Result<Event> {
        let token = self.peek_token()?;
        let start_mark = token.start_mark;
        let mut end_mark = token.start_mark;
        if self.check(&[Kind::DocumentEnd])? {
            let token = self.get_token()?;
            end_mark = token.end_mark;
        }
        self.state = Some(State::DocumentStart);
        Ok(Self::event(EventKind::DocumentEnd, start_mark, end_mark))
    }

    fn parse_document_content(&mut self) -> Result<Event> {
        if self.check(&[
            Kind::Directive,
            Kind::DocumentStart,
            Kind::DocumentEnd,
            Kind::StreamEnd,
        ])? {
            let mark = self.peek_token()?.start_mark;
            self.state = self.pop_state();
            Ok(Self::empty_scalar(mark))
        } else {
            self.parse_node(true, false)
        }
    }

    fn process_directives(&mut self) -> Result<()> {
        let mut yaml_version_seen = false;
        self.tag_handles = HashMap::new();
        while self.check(&[Kind::Directive])? {
            let token = self.get_token()?;
            if let TokenKind::Directive { name, value } = &token.kind {
                if name == "YAML" {
                    if yaml_version_seen {
                        return Err(parser_error(
                            None,
                            None,
                            "found duplicate YAML directive".to_owned(),
                            token.start_mark,
                        ));
                    }
                    if let DirectiveValue::Yaml(major) = value
                        && *major != 1
                    {
                        return Err(parser_error(
                            None,
                            None,
                            "found incompatible YAML document (version 1.* is required)".to_owned(),
                            token.start_mark,
                        ));
                    }
                    yaml_version_seen = true;
                } else if name == "TAG"
                    && let DirectiveValue::Tag(handle, prefix) = value
                {
                    if self.tag_handles.contains_key(handle) {
                        return Err(parser_error(
                            None,
                            None,
                            format!("duplicate tag handle {}", str_repr(handle)),
                            token.start_mark,
                        ));
                    }
                    self.tag_handles.insert(handle.clone(), prefix.clone());
                }
            }
        }
        for (k, v) in default_tags() {
            self.tag_handles.entry(k).or_insert(v);
        }
        Ok(())
    }

    fn parse_node(&mut self, block: bool, indentless_sequence: bool) -> Result<Event> {
        if self.check(&[Kind::Alias])? {
            let token = self.get_token()?;
            let TokenKind::Alias(name) = token.kind else {
                checked_token_kind()
            };
            self.state = self.pop_state();
            return Ok(Self::event(
                EventKind::Alias(name),
                token.start_mark,
                token.end_mark,
            ));
        }
        let mut anchor = None;
        let mut tag: Option<(Option<String>, String)> = None;
        let mut start_mark = None;
        let mut end_mark = None;
        let mut tag_mark = None;
        if self.check(&[Kind::Anchor])? {
            let token = self.get_token()?;
            start_mark = Some(token.start_mark);
            end_mark = Some(token.end_mark);
            if let TokenKind::Anchor(a) = token.kind {
                anchor = Some(a);
            }
            if self.check(&[Kind::Tag])? {
                let token = self.get_token()?;
                tag_mark = Some(token.start_mark);
                end_mark = Some(token.end_mark);
                if let TokenKind::Tag(h, s) = token.kind {
                    tag = Some((h, s));
                }
            }
        } else if self.check(&[Kind::Tag])? {
            let token = self.get_token()?;
            start_mark = Some(token.start_mark);
            tag_mark = Some(token.start_mark);
            end_mark = Some(token.end_mark);
            if let TokenKind::Tag(h, s) = token.kind {
                tag = Some((h, s));
            }
            if self.check(&[Kind::Anchor])? {
                let token = self.get_token()?;
                end_mark = Some(token.end_mark);
                if let TokenKind::Anchor(a) = token.kind {
                    anchor = Some(a);
                }
            }
        }
        let tag: Option<String> = match tag {
            Some((Some(handle), suffix)) => match self.tag_handles.get(&handle) {
                Some(prefix) => Some(format!("{prefix}{suffix}")),
                None => {
                    return Err(Error::Marked(MarkedError::new(
                        Some("while parsing a node"),
                        start_mark,
                        format!("found undefined tag handle {}", str_repr(&handle)),
                        tag_mark,
                    )));
                }
            },
            Some((None, suffix)) => Some(suffix),
            None => None,
        };
        let (start_mark, mut end_mark) = match start_mark {
            Some(s) => (s, end_mark.unwrap_or(s)),
            None => {
                let m = self.peek_token()?.start_mark;
                (m, m)
            }
        };
        let implicit = tag.is_none() || tag.as_deref() == Some("!");
        if indentless_sequence && self.check(&[Kind::BlockEntry])? {
            end_mark = self.peek_token()?.end_mark;
            self.state = Some(State::IndentlessSequenceEntry);
            return Ok(Self::event(
                EventKind::SequenceStart { anchor, tag },
                start_mark,
                end_mark,
            ));
        }
        if self.check(&[Kind::Scalar])? {
            let token = self.get_token()?;
            end_mark = token.end_mark;
            let TokenKind::Scalar { value, plain, .. } = token.kind else {
                checked_token_kind()
            };
            let implicit = if (plain && tag.is_none()) || tag.as_deref() == Some("!") {
                (true, false)
            } else if tag.is_none() {
                (false, true)
            } else {
                (false, false)
            };
            self.state = self.pop_state();
            return Ok(Self::event(
                EventKind::Scalar {
                    anchor,
                    tag,
                    implicit,
                    value,
                },
                start_mark,
                end_mark,
            ));
        }
        if self.check(&[Kind::FlowSequenceStart])? {
            end_mark = self.peek_token()?.end_mark;
            self.state = Some(State::FlowSequenceFirstEntry);
            return Ok(Self::event(
                EventKind::SequenceStart { anchor, tag },
                start_mark,
                end_mark,
            ));
        }
        if self.check(&[Kind::FlowMappingStart])? {
            end_mark = self.peek_token()?.end_mark;
            self.state = Some(State::FlowMappingFirstKey);
            return Ok(Self::event(
                EventKind::MappingStart { anchor, tag },
                start_mark,
                end_mark,
            ));
        }
        if block && self.check(&[Kind::BlockSequenceStart])? {
            end_mark = self.peek_token()?.start_mark;
            self.state = Some(State::BlockSequenceFirstEntry);
            return Ok(Self::event(
                EventKind::SequenceStart { anchor, tag },
                start_mark,
                end_mark,
            ));
        }
        if block && self.check(&[Kind::BlockMappingStart])? {
            end_mark = self.peek_token()?.start_mark;
            self.state = Some(State::BlockMappingFirstKey);
            return Ok(Self::event(
                EventKind::MappingStart { anchor, tag },
                start_mark,
                end_mark,
            ));
        }
        if anchor.is_some() || tag.is_some() {
            self.state = self.pop_state();
            return Ok(Self::event(
                EventKind::Scalar {
                    anchor,
                    tag,
                    implicit: (implicit, false),
                    value: String::new(),
                },
                start_mark,
                end_mark,
            ));
        }
        let node = if block { "block" } else { "flow" };
        let token = self.peek_token()?;
        Err(parser_error(
            Some(&format!("while parsing a {node} node")),
            Some(start_mark),
            format!(
                "expected the node content, but found {}",
                str_repr(token.kind.id())
            ),
            token.start_mark,
        ))
    }

    fn parse_block_sequence_first_entry(&mut self) -> Result<Event> {
        let token = self.get_token()?;
        self.marks.push(token.start_mark);
        self.parse_block_sequence_entry()
    }

    fn parse_block_sequence_entry(&mut self) -> Result<Event> {
        if self.check(&[Kind::BlockEntry])? {
            let token = self.get_token()?;
            if !self.check(&[Kind::BlockEntry, Kind::BlockEnd])? {
                self.states.push(State::BlockSequenceEntry);
                return self.parse_node(true, false);
            }
            self.state = Some(State::BlockSequenceEntry);
            return Ok(Self::empty_scalar(token.end_mark));
        }
        if !self.check(&[Kind::BlockEnd])? {
            let token = self.peek_token()?;
            return Err(parser_error(
                Some("while parsing a block collection"),
                self.marks.last().copied(),
                format!(
                    "expected <block end>, but found {}",
                    str_repr(token.kind.id())
                ),
                token.start_mark,
            ));
        }
        let token = self.get_token()?;
        self.state = self.pop_state();
        self.marks.pop();
        Ok(Self::event(
            EventKind::SequenceEnd,
            token.start_mark,
            token.end_mark,
        ))
    }

    fn parse_indentless_sequence_entry(&mut self) -> Result<Event> {
        if self.check(&[Kind::BlockEntry])? {
            let token = self.get_token()?;
            if !self.check(&[Kind::BlockEntry, Kind::Key, Kind::Value, Kind::BlockEnd])? {
                self.states.push(State::IndentlessSequenceEntry);
                return self.parse_node(true, false);
            }
            self.state = Some(State::IndentlessSequenceEntry);
            return Ok(Self::empty_scalar(token.end_mark));
        }
        let token = self.peek_token()?;
        self.state = self.pop_state();
        Ok(Self::event(
            EventKind::SequenceEnd,
            token.start_mark,
            token.start_mark,
        ))
    }

    fn parse_block_mapping_first_key(&mut self) -> Result<Event> {
        let token = self.get_token()?;
        self.marks.push(token.start_mark);
        self.parse_block_mapping_key()
    }

    fn parse_block_mapping_key(&mut self) -> Result<Event> {
        if self.check(&[Kind::Key])? {
            let token = self.get_token()?;
            if !self.check(&[Kind::Key, Kind::Value, Kind::BlockEnd])? {
                self.states.push(State::BlockMappingValue);
                return self.parse_node(true, true);
            }
            self.state = Some(State::BlockMappingValue);
            return Ok(Self::empty_scalar(token.end_mark));
        }
        if !self.check(&[Kind::BlockEnd])? {
            let token = self.peek_token()?;
            return Err(parser_error(
                Some("while parsing a block mapping"),
                self.marks.last().copied(),
                format!(
                    "expected <block end>, but found {}",
                    str_repr(token.kind.id())
                ),
                token.start_mark,
            ));
        }
        let token = self.get_token()?;
        self.state = self.pop_state();
        self.marks.pop();
        Ok(Self::event(
            EventKind::MappingEnd,
            token.start_mark,
            token.end_mark,
        ))
    }

    fn parse_block_mapping_value(&mut self) -> Result<Event> {
        if self.check(&[Kind::Value])? {
            let token = self.get_token()?;
            if !self.check(&[Kind::Key, Kind::Value, Kind::BlockEnd])? {
                self.states.push(State::BlockMappingKey);
                return self.parse_node(true, true);
            }
            self.state = Some(State::BlockMappingKey);
            return Ok(Self::empty_scalar(token.end_mark));
        }
        self.state = Some(State::BlockMappingKey);
        let token = self.peek_token()?;
        Ok(Self::empty_scalar(token.start_mark))
    }

    fn parse_flow_sequence_entry(&mut self, first: bool, take_start: bool) -> Result<Event> {
        if take_start {
            let token = self.get_token()?;
            self.marks.push(token.start_mark);
        }
        if !self.check(&[Kind::FlowSequenceEnd])? {
            if !first {
                if self.check(&[Kind::FlowEntry])? {
                    self.get_token()?;
                } else {
                    let token = self.peek_token()?;
                    return Err(parser_error(
                        Some("while parsing a flow sequence"),
                        self.marks.last().copied(),
                        format!("expected ',' or ']', but got {}", str_repr(token.kind.id())),
                        token.start_mark,
                    ));
                }
            }
            if self.check(&[Kind::Key])? {
                let token = self.peek_token()?;
                self.state = Some(State::FlowSequenceEntryMappingKey);
                return Ok(Self::event(
                    EventKind::MappingStart {
                        anchor: None,
                        tag: None,
                    },
                    token.start_mark,
                    token.end_mark,
                ));
            } else if !self.check(&[Kind::FlowSequenceEnd])? {
                self.states.push(State::FlowSequenceEntry);
                return self.parse_node(false, false);
            }
        }
        let token = self.get_token()?;
        self.state = self.pop_state();
        self.marks.pop();
        Ok(Self::event(
            EventKind::SequenceEnd,
            token.start_mark,
            token.end_mark,
        ))
    }

    fn parse_flow_sequence_entry_mapping_key(&mut self) -> Result<Event> {
        let token = self.get_token()?;
        if !self.check(&[Kind::Value, Kind::FlowEntry, Kind::FlowSequenceEnd])? {
            self.states.push(State::FlowSequenceEntryMappingValue);
            return self.parse_node(false, false);
        }
        self.state = Some(State::FlowSequenceEntryMappingValue);
        Ok(Self::empty_scalar(token.end_mark))
    }

    fn parse_flow_sequence_entry_mapping_value(&mut self) -> Result<Event> {
        if self.check(&[Kind::Value])? {
            let token = self.get_token()?;
            if !self.check(&[Kind::FlowEntry, Kind::FlowSequenceEnd])? {
                self.states.push(State::FlowSequenceEntryMappingEnd);
                return self.parse_node(false, false);
            }
            self.state = Some(State::FlowSequenceEntryMappingEnd);
            return Ok(Self::empty_scalar(token.end_mark));
        }
        self.state = Some(State::FlowSequenceEntryMappingEnd);
        let token = self.peek_token()?;
        Ok(Self::empty_scalar(token.start_mark))
    }

    fn parse_flow_sequence_entry_mapping_end(&mut self) -> Result<Event> {
        self.state = Some(State::FlowSequenceEntry);
        let token = self.peek_token()?;
        Ok(Self::event(
            EventKind::MappingEnd,
            token.start_mark,
            token.start_mark,
        ))
    }

    fn parse_flow_mapping_key(&mut self, first: bool, take_start: bool) -> Result<Event> {
        if take_start {
            let token = self.get_token()?;
            self.marks.push(token.start_mark);
        }
        if !self.check(&[Kind::FlowMappingEnd])? {
            if !first {
                if self.check(&[Kind::FlowEntry])? {
                    self.get_token()?;
                } else {
                    let token = self.peek_token()?;
                    return Err(parser_error(
                        Some("while parsing a flow mapping"),
                        self.marks.last().copied(),
                        format!(
                            "expected ',' or '}}', but got {}",
                            str_repr(token.kind.id())
                        ),
                        token.start_mark,
                    ));
                }
            }
            if self.check(&[Kind::Key])? {
                let token = self.get_token()?;
                if !self.check(&[Kind::Value, Kind::FlowEntry, Kind::FlowMappingEnd])? {
                    self.states.push(State::FlowMappingValue);
                    return self.parse_node(false, false);
                }
                self.state = Some(State::FlowMappingValue);
                return Ok(Self::empty_scalar(token.end_mark));
            } else if !self.check(&[Kind::FlowMappingEnd])? {
                self.states.push(State::FlowMappingEmptyValue);
                return self.parse_node(false, false);
            }
        }
        let token = self.get_token()?;
        self.state = self.pop_state();
        self.marks.pop();
        Ok(Self::event(
            EventKind::MappingEnd,
            token.start_mark,
            token.end_mark,
        ))
    }

    fn parse_flow_mapping_value(&mut self) -> Result<Event> {
        if self.check(&[Kind::Value])? {
            let token = self.get_token()?;
            if !self.check(&[Kind::FlowEntry, Kind::FlowMappingEnd])? {
                self.states.push(State::FlowMappingKey);
                return self.parse_node(false, false);
            }
            self.state = Some(State::FlowMappingKey);
            return Ok(Self::empty_scalar(token.end_mark));
        }
        self.state = Some(State::FlowMappingKey);
        let token = self.peek_token()?;
        Ok(Self::empty_scalar(token.start_mark))
    }

    fn parse_flow_mapping_empty_value(&mut self) -> Result<Event> {
        self.state = Some(State::FlowMappingKey);
        let mark = self.peek_token()?.start_mark;
        Ok(Self::empty_scalar(mark))
    }

    fn empty_scalar(mark: Mark) -> Event {
        Self::event(
            EventKind::Scalar {
                anchor: None,
                tag: None,
                implicit: (true, false),
                value: String::new(),
            },
            mark,
            mark,
        )
    }
}

/// The token kind was checked just before; this cannot happen.
fn checked_token_kind() -> ! {
    unreachable!("token kind checked before use")
}
