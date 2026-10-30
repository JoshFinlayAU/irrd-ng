//! `RPSLParserMessages` (`irrd/rpsl/parser_state.py`).

use std::fmt;

/// Severity of a parser message. v4 only ever uses these two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Level {
    /// `INFO`
    Info,
    /// `ERROR`
    Error,
}

impl Level {
    /// The level as v4 prints it.
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Error => "ERROR",
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The ordered INFO/ERROR messages produced while parsing one object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Messages {
    items: Vec<(Level, String)>,
}

impl Messages {
    /// All messages in the order they were produced.
    pub fn all(&self) -> &[(Level, String)] {
        &self.items
    }

    /// Message texts at `ERROR` level, in order.
    pub fn errors(&self) -> impl Iterator<Item = &str> {
        self.items
            .iter()
            .filter(|(l, _)| *l == Level::Error)
            .map(|(_, m)| m.as_str())
    }

    /// Message texts at `INFO` level, in order.
    pub fn infos(&self) -> impl Iterator<Item = &str> {
        self.items
            .iter()
            .filter(|(l, _)| *l == Level::Info)
            .map(|(_, m)| m.as_str())
    }

    /// Whether any `ERROR` was recorded.
    pub fn has_errors(&self) -> bool {
        self.items.iter().any(|(l, _)| *l == Level::Error)
    }

    /// Record an `INFO` message.
    pub fn info(&mut self, msg: impl Into<String>) {
        self.items.push((Level::Info, msg.into()));
    }

    /// Record an `ERROR` message.
    pub fn error(&mut self, msg: impl Into<String>) {
        self.items.push((Level::Error, msg.into()));
    }

    /// Append another message list (`merge_messages`).
    pub fn merge(&mut self, other: Messages) {
        self.items.extend(other.items);
    }
}

impl fmt::Display for Messages {
    /// `str(messages)`: one `LEVEL: text` per line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (level, msg)) in self.items.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            write!(f, "{level}: {msg}")?;
        }
        Ok(())
    }
}
