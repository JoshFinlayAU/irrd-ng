//! GraphQL as IRRd 4.5.4 serves it: a port of the parts of graphql-core
//! 3.3.0 and ariadne 1.1.1 that IRRd uses, so that parsing, validation
//! and execution errors, introspection and the response JSON are the same
//! byte for byte.
//!
//! The crate knows nothing about IRRd: the schema comes from SDL, and the
//! application supplies [`Resolvers`] and [`ScalarParsers`].

#![deny(unsafe_code)]

pub mod ast;
mod coerce;
mod cost;
pub mod error;
mod execution;
mod overlap;
pub mod parser;
pub mod schema;
mod suggest;
mod validation;
pub mod value;

pub use coerce::{ScalarError, ScalarParsers};
pub use error::GraphQLError;
pub use execution::{ExecutionResult, FieldInfo, ResolveError, Resolvers};
pub use schema::Schema;
pub use value::Value;

/// IRRd's `MAX_GRAPHQL_QUERY_COST`.
pub const MAX_QUERY_COST: i64 = 2500;

/// The outcome of [`graphql()`]: ariadne's `(success, result)`, or a
/// crash that v4 answers with a 500.
#[derive(Debug)]
pub enum Outcome {
    /// `(success, result)`: the JSON response body is `result`.
    Result(bool, Value),
    /// An exception escaped ariadne (Starlette answers 500).
    Crash(String),
}

/// What the request's extensions report: the `sql_queries` an `sqlTrace`
/// collected.
pub trait Extensions {
    /// `context["sql_queries"]`, if set.
    fn sql_queries(&self) -> Option<Vec<String>>;
}

/// `ariadne.graphql()` with IRRd's `QueryMetadataExtension` and
/// `error_formatter`. `elapsed` gives the `execution` time when called.
pub fn graphql(
    schema: &Schema,
    scalars: &dyn ScalarParsers,
    resolvers: &dyn Resolvers,
    extensions: &dyn Extensions,
    data: &Value,
    elapsed: &dyn Fn() -> f64,
) -> Outcome {
    let finish = |mut response: Vec<(String, Value)>| -> Vec<(String, Value)> {
        let mut ext: Vec<(String, Value)> = vec![("execution".into(), Value::Float(elapsed()))];
        if let Some(q) = extensions.sql_queries() {
            ext.push(("sql_query_count".into(), Value::Int(q.len() as i128)));
            ext.push((
                "sql_queries".into(),
                Value::List(q.into_iter().map(Value::Str).collect()),
            ));
        }
        response.push(("extensions".into(), Value::Object(ext)));
        response
    };
    let errors_only = |errors: Vec<Value>| -> Outcome {
        Outcome::Result(
            false,
            Value::Object(finish(vec![("errors".into(), Value::List(errors))])),
        )
    };

    // validate_data()
    let Value::Object(_) = data else {
        return errors_only(vec![
            GraphQLError::plain("Operation data should be a JSON object").formatted(&[]),
        ]);
    };
    let query = match data.get("query") {
        Some(Value::Str(q)) if !q.is_empty() => q.clone(),
        _ => {
            return errors_only(vec![
                GraphQLError::plain("The query must be a string.").formatted(&[]),
            ]);
        }
    };
    let variables = match data.get("variables") {
        None | Some(Value::Null) => None,
        Some(v @ Value::Object(_)) => Some(v.clone()),
        Some(_) => {
            return errors_only(vec![
                GraphQLError::plain("Query variables must be a null or an object.").formatted(&[]),
            ]);
        }
    };
    let operation_name = match data.get("operationName") {
        None | Some(Value::Null) => None,
        Some(Value::Str(s)) => Some(s.clone()),
        Some(other) => {
            return errors_only(vec![
                GraphQLError::plain(format!(
                    "\"{}\" is not a valid operation name.",
                    py_str(other)
                ))
                .formatted(&[]),
            ]);
        }
    };

    let body_chars: Vec<char> = query.chars().collect();
    let doc = match parser::parse(&body_chars) {
        Ok(d) => d,
        Err(e) => {
            let err = GraphQLError::new(format!("Syntax Error: {}", e.description), vec![e.pos]);
            return errors_only(vec![err.formatted(&body_chars)]);
        }
    };

    let errors = validation::validate(schema, scalars, &doc, &body_chars, Some(MAX_QUERY_COST));
    let errors = match errors {
        Ok(e) => e,
        Err(()) => {
            return Outcome::Crash("RecursionError: maximum recursion depth exceeded".into());
        }
    };
    if !errors.is_empty() {
        return errors_only(errors.iter().map(|e| e.formatted(&body_chars)).collect());
    }

    // validate_operation_is_not_subscription()
    let ops: Vec<&ast::OperationDefinition> = doc
        .definitions
        .iter()
        .filter_map(|d| match d {
            ast::Definition::Operation(o) => Some(o),
            _ => None,
        })
        .collect();
    match &operation_name {
        Some(n) => {
            if ops.iter().any(|o| {
                o.name.as_ref().is_some_and(|x| x.value == *n)
                    && o.operation == ast::OperationType::Subscription
            }) {
                return errors_only(vec![
                    GraphQLError::plain(format!(
                        "Operation '{n}' is a subscription and can only be executed over a WebSocket connection."
                    ))
                    .formatted(&[]),
                ]);
            }
        }
        None => {
            if ops.len() == 1 && ops[0].operation == ast::OperationType::Subscription {
                return errors_only(vec![
                    GraphQLError::plain(
                        "Subscription operations can only be executed over a WebSocket connection.",
                    )
                    .formatted(&[]),
                ]);
            }
        }
    }

    let result = execution::execute(
        schema,
        scalars,
        resolvers,
        &doc,
        operation_name.as_deref(),
        variables.as_ref(),
    );
    let success = result.data.is_some();
    let mut response = vec![("data".to_owned(), result.data.unwrap_or(Value::Null))];
    if !result.errors.is_empty() {
        response.push((
            "errors".into(),
            Value::List(
                result
                    .errors
                    .iter()
                    .map(|e| e.formatted(&body_chars))
                    .collect(),
            ),
        ));
    }
    Outcome::Result(success, Value::Object(finish(response)))
}

/// Python's `str()` of a JSON value.
fn py_str(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::Int(i) => i.to_string(),
        Value::BigInt(s) => s.clone(),
        Value::Float(f) => value::float_repr(*f),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        Value::List(l) => format!("[{}]", l.iter().map(py_repr).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter()
                .map(|(k, v)| format!("{}: {}", value::str_repr(k), py_repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Python's `repr()` of a JSON value.
fn py_repr(v: &Value) -> String {
    match v {
        Value::Str(s) => value::str_repr(s),
        other => py_str(other),
    }
}
