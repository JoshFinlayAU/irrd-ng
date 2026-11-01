//! Input coercion: graphql-core's `coerce_input_value`,
//! `coerce_input_literal`, `validate_input_value`, `validate_input_literal`
//! and the built-in scalars, with their messages.

use std::collections::HashMap;

use crate::ast::{self, ValueNode};
use crate::error::{GraphQLError, PathSeg, print_value};
use crate::schema::{InputValue, Kind, Schema, TypeId, TypeRef};
use crate::suggest::{did_you_mean_with, suggestion_list};
use crate::value::{Value, float_repr, inspect};

/// Why a custom scalar's parser rejected a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScalarError {
    /// It raised a `GraphQLError` with this message.
    GraphQL(String),
    /// It raised another exception, shown as `str(exception)`.
    Other(String),
}

/// Parsers for custom scalars (ariadne's `value_parser`).
pub trait ScalarParsers: Send + Sync {
    /// `parse_value(value)` for the scalar `name`.
    fn parse_value(&self, name: &str, value: &Value) -> Result<Value, ScalarError>;
}

/// Coerced variable values: `None` where a variable was not provided.
pub(crate) type Variables = HashMap<String, Value>;

/// A leaf coercion failure: a `GraphQLError` (with the node it names, if
/// any) or another exception.
#[derive(Debug, Clone)]
pub(crate) enum LeafError {
    GraphQL(String, Option<usize>),
    Other(String),
}

const MAX_INT: i128 = 2_147_483_647;
const MIN_INT: i128 = -2_147_483_648;

/// A built-in scalar's `coerce_input_value()`.
fn builtin_input_value(name: &str, v: &Value) -> Result<Value, LeafError> {
    let gerr = |m: String| Err(LeafError::GraphQL(m, None));
    match name {
        "Int" => match v {
            Value::Int(i) if (MIN_INT..=MAX_INT).contains(i) => Ok(Value::Int(*i)),
            Value::Int(_) | Value::BigInt(_) => gerr(format!(
                "Int cannot represent non 32-bit signed integer value: {}",
                inspect(v)
            )),
            Value::Float(f) => {
                if !f.is_finite() || f.trunc() != *f {
                    gerr(format!("Int cannot represent non-integer value: {}", inspect(v)))
                } else if (MIN_INT as f64..=MAX_INT as f64).contains(f) {
                    Ok(Value::Int(*f as i128))
                } else {
                    gerr(format!(
                        "Int cannot represent non 32-bit signed integer value: {}",
                        inspect(v)
                    ))
                }
            }
            _ => gerr(format!("Int cannot represent non-integer value: {}", inspect(v))),
        },
        "Float" => match v {
            Value::Float(f) if f.is_finite() => Ok(Value::Float(*f)),
            Value::Int(i) => {
                let f = *i as f64;
                if f as i128 != *i {
                    gerr(format!(
                        "Float cannot represent non numeric value: {} (value would lose precision)",
                        inspect(v)
                    ))
                } else {
                    Ok(Value::Float(f))
                }
            }
            Value::BigInt(_) => gerr(format!(
                "Float cannot represent non numeric value: {} (value would lose precision)",
                inspect(v)
            )),
            _ => gerr(format!("Float cannot represent non numeric value: {}", inspect(v))),
        },
        "String" => match v {
            Value::Str(s) => Ok(Value::Str(s.clone())),
            _ => gerr(format!(
                "String cannot represent a non string value: {}",
                inspect(v)
            )),
        },
        "Boolean" => match v {
            Value::Bool(b) => Ok(Value::Bool(*b)),
            _ => gerr(format!(
                "Boolean cannot represent a non boolean value: {}",
                inspect(v)
            )),
        },
        "ID" => match v {
            Value::Str(s) => Ok(Value::Str(s.clone())),
            Value::Int(i) => Ok(Value::Str(i.to_string())),
            Value::BigInt(s) => Ok(Value::Str(s.clone())),
            Value::Float(f) if f.is_finite() && f.trunc() == *f => {
                Ok(Value::Str(format!("{}", *f as i128)))
            }
            _ => gerr(format!("ID cannot represent value: {}", inspect(v))),
        },
        _ => Ok(v.clone()),
    }
}

/// A built-in scalar's `coerce_input_literal()`.
fn builtin_input_literal(name: &str, node: &ValueNode) -> Result<Value, LeafError> {
    let gerr = |m: String| Err(LeafError::GraphQL(m, Some(node.pos())));
    match name {
        "Int" => match node {
            ValueNode::Int(_, s) => match crate::value::int_value(s) {
                Value::Int(i) if (MIN_INT..=MAX_INT).contains(&i) => Ok(Value::Int(i)),
                _ => gerr(format!(
                    "Int cannot represent non 32-bit signed integer value: {}",
                    print_value(node)
                )),
            },
            _ => gerr(format!(
                "Int cannot represent non-integer value: {}",
                print_value(node)
            )),
        },
        "Float" => match node {
            ValueNode::Int(_, s) | ValueNode::Float(_, s) => {
                Ok(Value::Float(s.parse::<f64>().unwrap_or(f64::NAN)))
            }
            _ => gerr(format!(
                "Float cannot represent non numeric value: {}",
                print_value(node)
            )),
        },
        "String" => match node {
            ValueNode::String(_, s, _) => Ok(Value::Str(s.clone())),
            _ => gerr(format!(
                "String cannot represent a non string value: {}",
                print_value(node)
            )),
        },
        "Boolean" => match node {
            ValueNode::Boolean(_, b) => Ok(Value::Bool(*b)),
            _ => gerr(format!(
                "Boolean cannot represent a non boolean value: {}",
                print_value(node)
            )),
        },
        "ID" => match node {
            ValueNode::String(_, s, _) | ValueNode::Int(_, s) => Ok(Value::Str(s.clone())),
            _ => gerr(format!(
                "ID cannot represent a non-string and non-integer value: {}",
                print_value(node)
            )),
        },
        _ => Ok(Value::Null),
    }
}

/// `value_from_ast_untyped()`; `None` for an unknown variable
/// (`Undefined`).
fn value_from_ast_untyped(node: &ValueNode, vars: Option<&Variables>) -> Option<Value> {
    Some(match node {
        ValueNode::Null(_) => Value::Null,
        ValueNode::Int(_, s) => crate::value::int_value(s),
        ValueNode::Float(_, s) => Value::Float(s.parse::<f64>().unwrap_or(f64::NAN)),
        ValueNode::String(_, s, _) | ValueNode::Enum(_, s) => Value::Str(s.clone()),
        ValueNode::Boolean(_, b) => Value::Bool(*b),
        ValueNode::List(_, items) => Value::List(
            items
                .iter()
                .map(|i| value_from_ast_untyped(i, vars).unwrap_or(Value::Null))
                .collect(),
        ),
        ValueNode::Object(_, fields) => {
            let mut o: Vec<(String, Value)> = Vec::new();
            for f in fields {
                let v = value_from_ast_untyped(&f.value, vars).unwrap_or(Value::Null);
                match o.iter_mut().find(|(k, _)| *k == f.name.value) {
                    Some(e) => e.1 = v,
                    None => o.push((f.name.value.clone(), v)),
                }
            }
            Value::Object(o)
        }
        ValueNode::Variable(v) => return vars?.get(&v.name.value).cloned(),
    })
}

/// The coercion engine for one schema.
pub(crate) struct Coercer<'a> {
    pub(crate) schema: &'a Schema,
    pub(crate) scalars: &'a dyn ScalarParsers,
}

/// `print_path_list()`
pub(crate) fn print_path_list(path: &[PathSeg]) -> String {
    if path.is_empty() {
        return String::new();
    }
    let mut s = " at ".to_owned();
    for p in path {
        match p {
            PathSeg::Index(i) => s.push_str(&format!("[{i}]")),
            PathSeg::Key(k) => s.push_str(&format!(".{k}")),
        }
    }
    s
}

impl<'a> Coercer<'a> {
    fn leaf_input_value(&self, id: TypeId, v: &Value) -> Result<Value, LeafError> {
        let t = self.schema.t(id);
        if t.kind == Kind::Enum {
            return match v {
                Value::Str(s) => {
                    if t.enum_values.iter().any(|e| e.name == *s) {
                        Ok(Value::Str(s.clone()))
                    } else {
                        Err(LeafError::GraphQL(
                            format!(
                                "Value '{s}' does not exist in '{}' enum.{}",
                                t.name,
                                self.did_you_mean_enum(id, s)
                            ),
                            None,
                        ))
                    }
                }
                _ => {
                    let vs = inspect(v);
                    Err(LeafError::GraphQL(
                        format!(
                            "Enum '{}' cannot represent non-string value: {vs}.{}",
                            t.name,
                            self.did_you_mean_enum(id, &vs)
                        ),
                        None,
                    ))
                }
            };
        }
        if crate::schema::SPECIFIED_SCALARS.contains(&t.name.as_str()) {
            return builtin_input_value(&t.name, v);
        }
        self.scalars.parse_value(&t.name, v).map_err(|e| match e {
            ScalarError::GraphQL(m) => LeafError::GraphQL(m, None),
            ScalarError::Other(m) => LeafError::Other(m),
        })
    }

    fn did_you_mean_enum(&self, id: TypeId, s: &str) -> String {
        let names: Vec<&str> = self
            .schema
            .t(id)
            .enum_values
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        did_you_mean_with(&suggestion_list(s, &names), Some("the enum value"))
    }

    fn leaf_input_literal(
        &self,
        id: TypeId,
        node: &ValueNode,
        vars: Option<&Variables>,
    ) -> Result<Value, LeafError> {
        let t = self.schema.t(id);
        if t.kind == Kind::Enum {
            let node = replace_variables(node, vars);
            return match &node {
                ValueNode::Enum(_, s) => {
                    if t.enum_values.iter().any(|e| e.name == *s) {
                        Ok(Value::Str(s.clone()))
                    } else {
                        let vs = print_value(&node);
                        Err(LeafError::GraphQL(
                            format!(
                                "Value '{vs}' does not exist in '{}' enum.{}",
                                t.name,
                                self.did_you_mean_enum(id, &vs)
                            ),
                            Some(node.pos()),
                        ))
                    }
                }
                _ => {
                    let vs = print_value(&node);
                    Err(LeafError::GraphQL(
                        format!(
                            "Enum '{}' cannot represent non-enum value: {vs}.{}",
                            t.name,
                            self.did_you_mean_enum(id, &vs)
                        ),
                        Some(node.pos()),
                    ))
                }
            };
        }
        if crate::schema::SPECIFIED_SCALARS.contains(&t.name.as_str()) {
            let node = replace_variables(node, vars);
            return builtin_input_literal(&t.name, &node);
        }
        // parse_literal: parse_value(value_from_ast_untyped(node)).
        let untyped = value_from_ast_untyped(node, vars);
        match untyped {
            // parse_value(Undefined): ariadne's parsers call int()/IP()
            // on it, which raise TypeError/ValueError.
            None => Err(LeafError::Other("Undefined".into())),
            Some(v) => self.leaf_input_value(id, &v),
        }
    }

    /// `coerce_input_value()`; `None` for `Undefined`.
    pub(crate) fn input_value(&self, v: Option<&Value>, t: &TypeRef) -> Option<Value> {
        match t {
            TypeRef::NonNull(inner) => match v {
                None | Some(Value::Null) => None,
                _ => self.input_value(v, inner),
            },
            _ if matches!(v, None | Some(Value::Null)) => Some(Value::Null),
            TypeRef::List(item) => match v {
                Some(Value::List(items)) => {
                    let mut out = Vec::with_capacity(items.len());
                    for i in items {
                        out.push(self.input_value(Some(i), item)?);
                    }
                    Some(Value::List(out))
                }
                _ => Some(Value::List(vec![self.input_value(v, item)?])),
            },
            TypeRef::Named(id) => {
                let v = v?;
                if self.schema.t(*id).kind == Kind::InputObject {
                    return self.input_object_value(*id, v);
                }
                self.leaf_input_value(*id, v).ok()
            }
        }
    }

    fn input_object_value(&self, id: TypeId, v: &Value) -> Option<Value> {
        let Value::Object(o) = v else { return None };
        let t = self.schema.t(id);
        if o.iter().any(|(k, _)| !t.input_fields.iter().any(|f| f.name == *k)) {
            return None;
        }
        let mut out: Vec<(String, Value)> = Vec::new();
        for f in &t.input_fields {
            match o.iter().find(|(k, _)| *k == f.name) {
                None => {
                    if is_required(f) {
                        return None;
                    }
                    if let Some(d) = self.default_value(f).ok().flatten() {
                        out.push((f.name.clone(), d));
                    }
                }
                Some((_, fv)) => out.push((f.name.clone(), self.input_value(Some(fv), &f.type_)?)),
            }
        }
        if t.is_one_of && (o.len() != 1 || out.len() != 1 || out[0].1 == Value::Null) {
            return None;
        }
        Some(Value::Object(out))
    }

    /// `coerce_default_value()`: `Ok(None)` for no default.
    pub(crate) fn default_value(&self, iv: &InputValue) -> Result<Option<Value>, String> {
        let Some(lit) = &iv.default_value else {
            return Ok(None);
        };
        match self.input_literal(lit, &iv.type_, None) {
            Some(v) => Ok(Some(v)),
            None => Err(format!(
                "Expected value of type '{}' to be valid, found: {}.",
                self.schema.type_str(&iv.type_),
                print_value(lit)
            )),
        }
    }

    /// `coerce_input_literal()`; `None` for `Undefined`.
    pub(crate) fn input_literal(
        &self,
        node: &ValueNode,
        t: &TypeRef,
        vars: Option<&Variables>,
    ) -> Option<Value> {
        if let ValueNode::Variable(var) = node {
            let v = vars.and_then(|m| m.get(&var.name.value)).cloned();
            if matches!(v, None | Some(Value::Null)) && t.is_non_null() {
                return None;
            }
            return v;
        }
        match t {
            TypeRef::NonNull(inner) => {
                if matches!(node, ValueNode::Null(_)) {
                    return None;
                }
                self.input_literal(node, inner, vars)
            }
            _ if matches!(node, ValueNode::Null(_)) => Some(Value::Null),
            TypeRef::List(item) => match node {
                ValueNode::List(_, items) => {
                    let mut out = Vec::new();
                    for i in items {
                        match self.input_literal(i, item, vars) {
                            Some(v) => out.push(v),
                            None => {
                                if let ValueNode::Variable(var) = i
                                    && !item.is_non_null()
                                    && matches!(
                                        vars.and_then(|m| m.get(&var.name.value)),
                                        None | Some(Value::Null)
                                    )
                                {
                                    out.push(Value::Null);
                                    continue;
                                }
                                return None;
                            }
                        }
                    }
                    Some(Value::List(out))
                }
                _ => Some(Value::List(vec![self.input_literal(node, item, vars)?])),
            },
            TypeRef::Named(id) => {
                let ty = self.schema.t(*id);
                if ty.kind == Kind::InputObject {
                    let ValueNode::Object(_, fields) = node else {
                        return None;
                    };
                    if fields
                        .iter()
                        .any(|f| !ty.input_fields.iter().any(|d| d.name == f.name.value))
                    {
                        return None;
                    }
                    let mut out: Vec<(String, Value)> = Vec::new();
                    for d in &ty.input_fields {
                        // The last node with this name wins, as in a dict.
                        let fnode = fields.iter().rev().find(|f| f.name.value == d.name);
                        let missing = match fnode {
                            None => true,
                            Some(f) => match &f.value {
                                ValueNode::Variable(v) => {
                                    vars.and_then(|m| m.get(&v.name.value)).is_none()
                                }
                                _ => false,
                            },
                        };
                        if missing {
                            if is_required(d) {
                                return None;
                            }
                            if let Some(dv) = self.default_value(d).ok().flatten() {
                                out.push((d.name.clone(), dv));
                            }
                        } else if let Some(f) = fnode {
                            out.push((d.name.clone(), self.input_literal(&f.value, &d.type_, vars)?));
                        }
                    }
                    return Some(Value::Object(out));
                }
                self.leaf_input_literal(*id, node, vars).ok()
            }
        }
    }

    /// `validate_input_value()`: reports `(message, path)`.
    pub(crate) fn validate_input_value(
        &self,
        v: Option<&Value>,
        t: &TypeRef,
        path: &mut Vec<PathSeg>,
        on_error: &mut dyn FnMut(GraphQLError, &[PathSeg]),
    ) {
        match t {
            TypeRef::NonNull(inner) => {
                match v {
                    None => on_error(
                        GraphQLError::plain(format!(
                            "Expected a value of non-null type '{}' to be provided.",
                            self.schema.type_str(t)
                        )),
                        path,
                    ),
                    Some(Value::Null) => on_error(
                        GraphQLError::plain(format!(
                            "Expected value of non-null type '{}' not to be None.",
                            self.schema.type_str(t)
                        )),
                        path,
                    ),
                    _ => self.validate_input_value(v, inner, path, on_error),
                }
            }
            _ if matches!(v, None | Some(Value::Null)) => {}
            TypeRef::List(item) => match v {
                Some(Value::List(items)) => {
                    for (i, x) in items.iter().enumerate() {
                        path.push(PathSeg::Index(i));
                        self.validate_input_value(Some(x), item, path, on_error);
                        path.pop();
                    }
                }
                _ => self.validate_input_value(v, item, path, on_error),
            },
            TypeRef::Named(id) => {
                let Some(v) = v else { return };
                let ty = self.schema.t(*id);
                if ty.kind == Kind::InputObject {
                    let Value::Object(o) = v else {
                        on_error(
                            GraphQLError::plain(format!(
                                "Expected value of type '{}' to be an object, found: {}.",
                                ty.name,
                                inspect(v)
                            )),
                            path,
                        );
                        return;
                    };
                    for f in &ty.input_fields {
                        match o.iter().find(|(k, _)| *k == f.name) {
                            None => {
                                if is_required(f) {
                                    on_error(
                                        GraphQLError::plain(format!(
                                            "Expected value of type '{}' to include required field '{}', found: {}.",
                                            ty.name,
                                            f.name,
                                            inspect(v)
                                        )),
                                        path,
                                    );
                                }
                            }
                            Some((_, fv)) => {
                                path.push(PathSeg::Key(f.name.clone()));
                                self.validate_input_value(Some(fv), &f.type_, path, on_error);
                                path.pop();
                            }
                        }
                    }
                    for (k, _) in o {
                        if !ty.input_fields.iter().any(|f| f.name == *k) {
                            let names: Vec<&str> =
                                ty.input_fields.iter().map(|f| f.name.as_str()).collect();
                            let s = did_you_mean_with(&suggestion_list(k, &names), None);
                            on_error(
                                GraphQLError::plain(format!(
                                    "Expected value of type '{}' not to include unknown field '{k}'{}: {}.",
                                    ty.name,
                                    if s.is_empty() {
                                        ", found".to_owned()
                                    } else {
                                        format!(".{s} Found")
                                    },
                                    inspect(v)
                                )),
                                path,
                            );
                        }
                    }
                    return;
                }
                match self.leaf_input_value(*id, v) {
                    Ok(_) => {}
                    Err(LeafError::GraphQL(m, _)) => on_error(GraphQLError::plain(m), path),
                    Err(LeafError::Other(e)) => on_error(
                        GraphQLError::plain(format!(
                            "Expected value of type '{}', but encountered error '{e}'; found: {}.",
                            ty.name,
                            inspect(v)
                        )),
                        path,
                    ),
                }
            }
        }
    }

    /// `validate_input_literal()`. With `vars` `None` the context is
    /// static (validation), where variables are not checked.
    pub(crate) fn validate_input_literal(
        &self,
        node: &ValueNode,
        t: &TypeRef,
        vars: Option<&Variables>,
        path: &mut Vec<PathSeg>,
        on_error: &mut dyn FnMut(GraphQLError, &[PathSeg]) -> bool,
    ) -> bool {
        // Returns false when on_error asked to stop (it raised).
        let ts = |t: &TypeRef| self.schema.type_str(t);
        if let ValueNode::Variable(var) = node {
            let Some(vars) = vars else { return true };
            let v = vars.get(&var.name.value);
            if t.is_non_null() {
                match v {
                    None => {
                        return on_error(
                            GraphQLError::new(
                                format!(
                                    "Expected variable '${}' provided to type '{}' to provide a runtime value.",
                                    var.name.value,
                                    ts(t)
                                ),
                                vec![var.pos],
                            ),
                            path,
                        );
                    }
                    Some(Value::Null) => {
                        return on_error(
                            GraphQLError::new(
                                format!(
                                    "Expected variable '${}' provided to non-null type '{}' not to be None.",
                                    var.name.value,
                                    ts(t)
                                ),
                                vec![var.pos],
                            ),
                            path,
                        );
                    }
                    _ => {}
                }
            }
            return true;
        }
        match t {
            TypeRef::NonNull(inner) => {
                if let ValueNode::Null(p) = node {
                    return on_error(
                        GraphQLError::new(
                            format!("Expected value of non-null type '{}' not to be None.", ts(t)),
                            vec![*p],
                        ),
                        path,
                    );
                }
                self.validate_input_literal(node, inner, vars, path, on_error)
            }
            _ if matches!(node, ValueNode::Null(_)) => true,
            TypeRef::List(item) => match node {
                ValueNode::List(_, items) => {
                    for (i, x) in items.iter().enumerate() {
                        path.push(PathSeg::Index(i));
                        let go = self.validate_input_literal(x, item, vars, path, on_error);
                        path.pop();
                        if !go {
                            return false;
                        }
                    }
                    true
                }
                _ => self.validate_input_literal(node, item, vars, path, on_error),
            },
            TypeRef::Named(id) => {
                let ty = self.schema.t(*id);
                if ty.kind == Kind::InputObject {
                    let ValueNode::Object(p, fields) = node else {
                        return on_error(
                            GraphQLError::new(
                                format!(
                                    "Expected value of type '{}' to be an object, found: {}.",
                                    ty.name,
                                    print_value(node)
                                ),
                                vec![node.pos()],
                            ),
                            path,
                        );
                    };
                    for d in &ty.input_fields {
                        match fields.iter().rev().find(|f| f.name.value == d.name) {
                            None => {
                                if is_required(d)
                                    && !on_error(
                                        GraphQLError::new(
                                            format!(
                                                "Expected value of type '{}' to include required field '{}', found: {}.",
                                                ty.name,
                                                d.name,
                                                print_value(node)
                                            ),
                                            vec![*p],
                                        ),
                                        path,
                                    )
                                {
                                    return false;
                                }
                            }
                            Some(f) => {
                                if let (ValueNode::Variable(v), Some(m)) = (&f.value, vars)
                                    && m.get(&v.name.value).is_none()
                                    && !is_required(d)
                                {
                                    continue;
                                }
                                path.push(PathSeg::Key(d.name.clone()));
                                let go =
                                    self.validate_input_literal(&f.value, &d.type_, vars, path, on_error);
                                path.pop();
                                if !go {
                                    return false;
                                }
                            }
                        }
                    }
                    for f in fields {
                        if !ty.input_fields.iter().any(|d| d.name == f.name.value) {
                            let names: Vec<&str> =
                                ty.input_fields.iter().map(|f| f.name.as_str()).collect();
                            let s = did_you_mean_with(&suggestion_list(&f.name.value, &names), None);
                            if !on_error(
                                GraphQLError::new(
                                    format!(
                                        "Expected value of type '{}' not to include unknown field '{}'{}: {}.",
                                        ty.name,
                                        f.name.value,
                                        if s.is_empty() {
                                            ", found".to_owned()
                                        } else {
                                            format!(".{s} Found")
                                        },
                                        print_value(node)
                                    ),
                                    vec![f.pos],
                                ),
                                path,
                            ) {
                                return false;
                            }
                        }
                    }
                    return true;
                }
                match self.leaf_input_literal(*id, node, vars) {
                    Ok(_) => true,
                    Err(LeafError::GraphQL(m, pos)) => {
                        on_error(GraphQLError::new(m, pos.into_iter().collect()), path)
                    }
                    Err(LeafError::Other(e)) => on_error(
                        GraphQLError::new(
                            format!(
                                "Expected value of type '{}', but encountered error '{e}'; found: {}.",
                                ty.name,
                                print_value(node)
                            ),
                            vec![node.pos()],
                        ),
                        path,
                    ),
                }
            }
        }
    }
}

/// `replace_variables()` for leaf literals: variables become literals of
/// their coerced values (only used for built-in scalars and enums, where
/// a variable reaching a leaf is already coerced).
fn replace_variables(node: &ValueNode, vars: Option<&Variables>) -> ValueNode {
    match node {
        ValueNode::Variable(v) => match vars.and_then(|m| m.get(&v.name.value)) {
            Some(val) => value_to_literal(val, v.pos),
            None => ValueNode::Null(v.pos),
        },
        ValueNode::List(p, items) => {
            ValueNode::List(*p, items.iter().map(|i| replace_variables(i, vars)).collect())
        }
        ValueNode::Object(p, fields) => ValueNode::Object(
            *p,
            fields
                .iter()
                .map(|f| ast::ObjectField {
                    pos: f.pos,
                    name: f.name.clone(),
                    value: replace_variables(&f.value, vars),
                })
                .collect(),
        ),
        n => n.clone(),
    }
}

fn value_to_literal(v: &Value, pos: usize) -> ValueNode {
    match v {
        Value::Null => ValueNode::Null(pos),
        Value::Bool(b) => ValueNode::Boolean(pos, *b),
        Value::Int(i) => ValueNode::Int(pos, i.to_string()),
        Value::BigInt(s) => ValueNode::Int(pos, s.clone()),
        Value::Float(f) => ValueNode::Float(pos, float_repr(*f)),
        Value::Str(s) => ValueNode::String(pos, s.clone(), false),
        Value::List(l) => ValueNode::List(pos, l.iter().map(|x| value_to_literal(x, pos)).collect()),
        Value::Object(o) => ValueNode::Object(
            pos,
            o.iter()
                .map(|(k, x)| ast::ObjectField {
                    pos,
                    name: ast::Name {
                        pos,
                        value: k.clone(),
                    },
                    value: value_to_literal(x, pos),
                })
                .collect(),
        ),
    }
}

/// `is_required_argument()` / `is_required_input_field()`
pub(crate) fn is_required(iv: &InputValue) -> bool {
    iv.type_.is_non_null() && iv.default_value.is_none()
}
