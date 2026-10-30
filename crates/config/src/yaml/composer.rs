//! `yaml/composer.py` and `yaml/resolver.py`.
//!
//! Nodes live in an arena so aliases can share them, as Python's node
//! objects are shared.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use super::parser::{EventKind, Parser};
use super::{Error, Mark, MarkedError};
use crate::python::str_repr;

pub(crate) type NodeId = usize;

#[derive(Clone, Debug)]
pub(crate) enum NodeValue {
    Scalar(String),
    Sequence(Vec<NodeId>),
    Mapping(Vec<(NodeId, NodeId)>),
}

#[derive(Clone, Debug)]
pub(crate) struct Node {
    pub(crate) tag: String,
    pub(crate) value: NodeValue,
    pub(crate) start_mark: Mark,
}

impl Node {
    /// The node's `id`, as shown in constructor errors.
    pub(crate) fn id(&self) -> &'static str {
        match self.value {
            NodeValue::Scalar(_) => "scalar",
            NodeValue::Sequence(_) => "sequence",
            NodeValue::Mapping(_) => "mapping",
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

const DEFAULT_SCALAR_TAG: &str = "tag:yaml.org,2002:str";
const DEFAULT_SEQUENCE_TAG: &str = "tag:yaml.org,2002:seq";
const DEFAULT_MAPPING_TAG: &str = "tag:yaml.org,2002:map";

/// Python's `re.match` with a pattern ending in `$`, which also matches
/// before a single trailing newline.
fn py_regex(body: &str) -> Regex {
    #[allow(clippy::expect_used)]
    Regex::new(&format!(r"\A(?:{body})\n?\z")).expect("static resolver pattern")
}

struct Resolver {
    tag: &'static str,
    first: &'static str,
    regex: Regex,
}

/// `Resolver.add_implicit_resolver` calls, in registration order.
static RESOLVERS: LazyLock<Vec<Resolver>> = LazyLock::new(|| {
    vec![
        Resolver {
            tag: "tag:yaml.org,2002:bool",
            first: "yYnNtTfFoO",
            regex: py_regex(
                "yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF",
            ),
        },
        Resolver {
            tag: "tag:yaml.org,2002:float",
            first: "-+0123456789.",
            regex: py_regex(
                r"[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)",
            ),
        },
        Resolver {
            tag: "tag:yaml.org,2002:int",
            first: "-+0123456789",
            regex: py_regex(
                r"[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+",
            ),
        },
        Resolver {
            tag: "tag:yaml.org,2002:merge",
            first: "<",
            regex: py_regex("<<"),
        },
        Resolver {
            tag: "tag:yaml.org,2002:null",
            first: "~nN\0",
            regex: py_regex("~|null|Null|NULL|"),
        },
        Resolver {
            tag: "tag:yaml.org,2002:timestamp",
            first: "0123456789",
            regex: py_regex(
                r"[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?",
            ),
        },
        Resolver {
            tag: "tag:yaml.org,2002:value",
            first: "=",
            regex: py_regex("="),
        },
        Resolver {
            tag: "tag:yaml.org,2002:yaml",
            first: "!&*",
            regex: py_regex(r"!|&|\*"),
        },
    ]
});

/// `BaseResolver.resolve` for a scalar.
fn resolve_scalar(value: &str, implicit: (bool, bool)) -> String {
    if implicit.0 {
        // The empty string is registered under the key '' (here '\0').
        let first = value.chars().next().unwrap_or('\0');
        for resolver in RESOLVERS.iter() {
            if resolver.first.contains(first) && resolver.regex.is_match(value) {
                return resolver.tag.to_owned();
            }
        }
    }
    DEFAULT_SCALAR_TAG.to_owned()
}

pub(crate) struct Composer {
    parser: Parser,
    anchors: HashMap<String, NodeId>,
    nodes: Vec<Node>,
}

impl Composer {
    pub(crate) fn new(parser: Parser) -> Self {
        Composer {
            parser,
            anchors: HashMap::new(),
            nodes: Vec::new(),
        }
    }

    pub(crate) fn nodes_mut(&mut self) -> &mut Vec<Node> {
        &mut self.nodes
    }

    pub(crate) fn reader_error(&self) -> Option<(usize, u32)> {
        self.parser.scanner.reader.error()
    }

    fn check_stream_end(&mut self) -> Result<bool> {
        Ok(matches!(
            self.parser.peek_event()?.map(|e| &e.kind),
            Some(EventKind::StreamEnd) | None
        ))
    }

    pub(crate) fn get_single_node(&mut self) -> Result<Option<NodeId>> {
        // Drop the STREAM-START event.
        self.parser.get_event()?;
        let mut document = None;
        if !self.check_stream_end()? {
            document = Some(self.compose_document()?);
        }
        if !self.check_stream_end()? {
            let event = self.parser.get_event()?;
            let start = event.map(|e| e.start_mark);
            let doc_mark = document.map(|d: NodeId| self.nodes[d].start_mark);
            return Err(Error::Marked(MarkedError::new(
                Some("expected a single document in the stream"),
                doc_mark,
                "but found another document",
                start,
            )));
        }
        self.parser.get_event()?;
        Ok(document)
    }

    fn compose_document(&mut self) -> Result<NodeId> {
        // Drop the DOCUMENT-START event.
        self.parser.get_event()?;
        let node = self.compose_node()?;
        // Drop the DOCUMENT-END event.
        self.parser.get_event()?;
        self.anchors.clear();
        Ok(node)
    }

    fn compose_node(&mut self) -> Result<NodeId> {
        let Some(event) = self.parser.peek_event()?.cloned() else {
            return Err(Error::Crash(crate::python::PyException::new(
                "AttributeError",
                "'NoneType' object has no attribute 'anchor'",
            )));
        };
        if let EventKind::Alias(anchor) = &event.kind {
            self.parser.get_event()?;
            return match self.anchors.get(anchor) {
                Some(id) => Ok(*id),
                None => Err(Error::Marked(MarkedError::new(
                    None,
                    None,
                    format!("found undefined alias {}", str_repr(anchor)),
                    Some(event.start_mark),
                ))),
            };
        }
        let anchor = match &event.kind {
            EventKind::Scalar { anchor, .. }
            | EventKind::SequenceStart { anchor, .. }
            | EventKind::MappingStart { anchor, .. } => anchor.clone(),
            _ => None,
        };
        if let Some(a) = &anchor
            && let Some(first) = self.anchors.get(a)
        {
            return Err(Error::Marked(MarkedError::new(
                Some(&format!(
                    "found duplicate anchor {}; first occurrence",
                    str_repr(a)
                )),
                Some(self.nodes[*first].start_mark),
                "second occurrence",
                Some(event.start_mark),
            )));
        }
        match event.kind {
            EventKind::Scalar {
                tag,
                implicit,
                value,
                ..
            } => {
                self.parser.get_event()?;
                let tag = match tag {
                    Some(t) if t != "!" => t,
                    _ => resolve_scalar(&value, implicit),
                };
                let id = self.push(Node {
                    tag,
                    value: NodeValue::Scalar(value),
                    start_mark: event.start_mark,
                });
                if let Some(a) = anchor {
                    self.anchors.insert(a, id);
                }
                Ok(id)
            }
            EventKind::SequenceStart { tag, .. } => {
                self.parser.get_event()?;
                let tag = match tag {
                    Some(t) if t != "!" => t,
                    _ => DEFAULT_SEQUENCE_TAG.to_owned(),
                };
                let id = self.push(Node {
                    tag,
                    value: NodeValue::Sequence(Vec::new()),
                    start_mark: event.start_mark,
                });
                if let Some(a) = anchor {
                    self.anchors.insert(a, id);
                }
                loop {
                    if matches!(
                        self.parser.peek_event()?.map(|e| &e.kind),
                        Some(EventKind::SequenceEnd) | None
                    ) {
                        break;
                    }
                    let child = self.compose_node()?;
                    if let NodeValue::Sequence(items) = &mut self.nodes[id].value {
                        items.push(child);
                    }
                }
                self.parser.get_event()?;
                Ok(id)
            }
            EventKind::MappingStart { tag, .. } => {
                self.parser.get_event()?;
                let tag = match tag {
                    Some(t) if t != "!" => t,
                    _ => DEFAULT_MAPPING_TAG.to_owned(),
                };
                let id = self.push(Node {
                    tag,
                    value: NodeValue::Mapping(Vec::new()),
                    start_mark: event.start_mark,
                });
                if let Some(a) = anchor {
                    self.anchors.insert(a, id);
                }
                loop {
                    if matches!(
                        self.parser.peek_event()?.map(|e| &e.kind),
                        Some(EventKind::MappingEnd) | None
                    ) {
                        break;
                    }
                    let key = self.compose_node()?;
                    let value = self.compose_node()?;
                    if let NodeValue::Mapping(items) = &mut self.nodes[id].value {
                        items.push((key, value));
                    }
                }
                self.parser.get_event()?;
                Ok(id)
            }
            _ => Err(Error::Crash(crate::python::PyException::new(
                "UnboundLocalError",
                "cannot access local variable 'node' where it is not associated with a value",
            ))),
        }
    }

    fn push(&mut self, node: Node) -> NodeId {
        self.nodes.push(node);
        self.nodes.len() - 1
    }
}
