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

    let (query, variables, operation_name) = match validate_data(data) {
        Ok(v) => v,
        Err(e) => return errors_only(vec![e.formatted(&[])]),
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

/// ariadne's `validate_data()`: the query, variables and operation name,
/// or the `GraphQLError` it raises.
fn validate_data(data: &Value) -> Result<(String, Option<Value>, Option<String>), GraphQLError> {
    let Value::Object(_) = data else {
        return Err(GraphQLError::plain(
            "Operation data should be a JSON object",
        ));
    };
    let query = match data.get("query") {
        Some(Value::Str(q)) if !q.is_empty() => q.clone(),
        _ => return Err(GraphQLError::plain("The query must be a string.")),
    };
    let variables = match data.get("variables") {
        None | Some(Value::Null) => None,
        Some(v @ Value::Object(_)) => Some(v.clone()),
        Some(_) => {
            return Err(GraphQLError::plain(
                "Query variables must be a null or an object.",
            ));
        }
    };
    let operation_name = match data.get("operationName") {
        None | Some(Value::Null) => None,
        Some(Value::Str(s)) => Some(s.clone()),
        Some(other) => {
            return Err(GraphQLError::plain(format!(
                "\"{}\" is not a valid operation name.",
                py_str(other)
            )));
        }
    };
    Ok((query, variables, operation_name))
}

/// What ariadne's `GraphQLWSHandler.process_single_message()` makes of a
/// `start` message's payload.
#[derive(Debug)]
pub enum WsStart {
    /// An `error` message with this payload: a syntax error, or the first
    /// error from subscribing (IRRd's schema has no subscription type, so
    /// every subscription fails validation).
    Error(Value),
    /// A query or mutation, which ariadne hands to the HTTP handler.
    Execute,
    /// An exception escaped the handler: the text of the Python exception.
    Crash(String),
}

/// `process_single_message()` up to the point where it either answers
/// or hands a query or mutation to the HTTP handler: `validate_data()`,
/// `parse_query()`, `get_operation_type()` and, for a subscription,
/// ariadne's `subscribe()`.
pub fn ws_start(schema: &Schema, scalars: &dyn ScalarParsers, data: &Value) -> WsStart {
    let (query, _variables, operation_name) = match validate_data(data) {
        Ok(v) => v,
        Err(e) => {
            return WsStart::Crash(format!(
                "graphql.error.graphql_error.GraphQLError: {}",
                e.message
            ));
        }
    };
    let body_chars: Vec<char> = query.chars().collect();
    let doc = match parser::parse(&body_chars) {
        Ok(d) => d,
        Err(e) => {
            let err = GraphQLError::new(format!("Syntax Error: {}", e.description), vec![e.pos]);
            return WsStart::Error(err.formatted(&body_chars));
        }
    };
    // ariadne.utils.get_operation_type(): with a name, the first
    // definition of that name, reading `.name` and `.operation` from
    // whatever node it meets; without one, the first operation.
    let mut found: Option<&ast::OperationDefinition> = None;
    match operation_name.as_deref().filter(|n| !n.is_empty()) {
        Some(n) => {
            for d in &doc.definitions {
                match d {
                    ast::Definition::Operation(o) => {
                        if o.name.as_ref().is_some_and(|x| x.value == n) {
                            found = Some(o);
                            break;
                        }
                    }
                    ast::Definition::Fragment(f) => {
                        if f.name.value == n {
                            return WsStart::Crash(
                                "AttributeError: 'FragmentDefinitionNode' object has no attribute 'operation'".into(),
                            );
                        }
                    }
                    ast::Definition::TypeSystem(t) => match &t.name {
                        None => {
                            return WsStart::Crash(
                                "AttributeError: definition node object has no attribute 'name'"
                                    .into(),
                            );
                        }
                        Some(x) if x.value == n => {
                            return WsStart::Crash(
                                "AttributeError: definition node object has no attribute 'operation'".into(),
                            );
                        }
                        Some(_) => {}
                    },
                }
            }
        }
        None => {
            found = doc.definitions.iter().find_map(|d| match d {
                ast::Definition::Operation(o) => Some(o),
                _ => None,
            });
        }
    }
    let Some(op) = found else {
        return WsStart::Crash("RuntimeError: Can't get GraphQL operation type".into());
    };
    if op.operation != ast::OperationType::Subscription {
        return WsStart::Execute;
    }
    match validation::validate(schema, scalars, &doc, &body_chars, Some(MAX_QUERY_COST)) {
        Err(()) => WsStart::Crash("RecursionError: maximum recursion depth exceeded".into()),
        Ok(errors) => match errors.first() {
            Some(e) => WsStart::Error(e.formatted(&body_chars)),
            // Unreachable with a schema without a subscription type, which
            // KnownOperationTypesRule reports; graphql-core's subscribe()
            // would answer this.
            None => WsStart::Error(
                GraphQLError::new(
                    "Schema is not configured to execute subscription operation.",
                    vec![op.pos],
                )
                .formatted(&body_chars),
            ),
        },
    }
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
