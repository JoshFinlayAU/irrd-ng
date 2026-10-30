//! A port of PyYAML 6.0.3's pure-Python `SafeLoader`.
//!
//! v4 reads `irrd.yaml` with `yaml.safe_load()` on an open text file, and
//! anything wrong with the file reaches the operator as
//! `Error parsing YAML file: ` followed by `str()` of PyYAML's exception,
//! with its own wording and its own idea of where the problem is. Getting
//! those bytes right, and getting YAML 1.1 typing right (`yes`/`no`/`on`/`off`
//! booleans, `0o`-less octal, sexagesimal numbers, timestamps, `<<` merges,
//! last-wins duplicate keys), needs PyYAML's scanner, parser, composer and
//! constructor, so this module follows them line for line. The structure and
//! names mirror `yaml/reader.py`, `scanner.py`, `parser.py`, `composer.py`,
//! `resolver.py` and `constructor.py` so the two can be read side by side.

mod composer;
mod constructor;
mod parser;
mod reader;
mod scanner;

use crate::python::{PyException, Value};

pub(crate) use scanner::utf8_error_reason;

/// A position in the stream, printed like PyYAML's `Mark.__str__` for a file
/// stream (no snippet, because PyYAML only keeps one for in-memory input).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mark {
    pub(crate) line: usize,
    pub(crate) column: usize,
}

/// `str()` of a PyYAML `MarkedYAMLError`.
#[derive(Clone, Debug)]
pub(crate) struct MarkedError {
    pub(crate) context: Option<String>,
    pub(crate) context_mark: Option<Mark>,
    pub(crate) problem: Option<String>,
    pub(crate) problem_mark: Option<Mark>,
}

impl MarkedError {
    pub(crate) fn new(
        context: Option<&str>,
        context_mark: Option<Mark>,
        problem: impl Into<String>,
        problem_mark: Option<Mark>,
    ) -> Self {
        Self {
            context: context.map(str::to_owned),
            context_mark,
            problem: Some(problem.into()),
            problem_mark,
        }
    }

    fn render(&self, name: &str) -> String {
        let mark = |m: &Mark| {
            format!(
                "  in \"{}\", line {}, column {}",
                name,
                m.line + 1,
                m.column + 1
            )
        };
        let mut lines = Vec::new();
        if let Some(context) = &self.context {
            lines.push(context.clone());
        }
        if let Some(cm) = &self.context_mark {
            let same =
                matches!((&self.problem, &self.problem_mark), (Some(_), Some(pm)) if pm == cm);
            if !same {
                lines.push(mark(cm));
            }
        }
        if let Some(problem) = &self.problem {
            lines.push(problem.clone());
        }
        if let Some(pm) = &self.problem_mark {
            lines.push(mark(pm));
        }
        lines.join("\n")
    }
}

/// Everything that can stop `yaml.safe_load` from returning a value.
#[derive(Clone, Debug)]
pub(crate) enum Error {
    /// A scanner, parser, composer or constructor error.
    Marked(MarkedError),
    /// A Python exception that is not a `YAMLError`, so v4 does not catch it.
    Crash(PyException),
}

impl From<MarkedError> for Error {
    fn from(e: MarkedError) -> Self {
        Error::Marked(e)
    }
}

impl From<PyException> for Error {
    fn from(e: PyException) -> Self {
        Error::Crash(e)
    }
}

/// Why loading failed, in the form v4 surfaces it.
#[derive(Clone, Debug)]
pub(crate) enum LoadError {
    /// `str(yaml.YAMLError)`.
    Yaml(String),
    /// Any other exception.
    Crash(PyException),
}

/// `yaml.safe_load(open(name))` where `text` is what the text-mode file read
/// returned (UTF-8 decoded, universal newlines translated).
pub(crate) fn safe_load(name: &str, text: &str) -> Result<Value, LoadError> {
    let reader = reader::Reader::new(text);
    let scanner = scanner::Scanner::new(reader);
    let parser = parser::Parser::new(scanner);
    let mut composer = composer::Composer::new(parser);
    let result = composer.get_single_node().and_then(|root| match root {
        Some(root) => constructor::construct_document(composer.nodes_mut(), root),
        None => Ok(Value::None),
    });
    // A reader error happens before anything the scanner does afterwards, so
    // it wins over whatever the degraded scan produced.
    if let Some((position, character)) = composer.reader_error() {
        return Err(LoadError::Yaml(reader_error(name, position, character)));
    }
    result.map_err(|e| match e {
        Error::Marked(m) => LoadError::Yaml(m.render(name)),
        Error::Crash(c) => LoadError::Crash(c),
    })
}

fn reader_error(name: &str, position: usize, character: u32) -> String {
    format!(
        "unacceptable character #x{character:04x}: special characters are not allowed\n  in \"{name}\", position {position}"
    )
}

#[cfg(test)]
mod tests;
