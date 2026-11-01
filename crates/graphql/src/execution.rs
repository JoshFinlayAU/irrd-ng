//! graphql-core's executor: operation selection, variable coercion, field
//! collection with `@skip`/`@include`, resolution, value completion with
//! null propagation, and introspection.

use std::collections::HashMap;

use crate::ast::*;
use crate::coerce::{Coercer, ScalarParsers, Variables, print_path_list};
use crate::error::{GraphQLError, PathSeg, print_value};
use crate::schema::{FieldRef, Kind, Schema, TypeId, TypeRef};
use crate::validation::get_argument_values;
use crate::value::{Value, float_repr, inspect};

/// An error raised by a resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// `raise GraphQLError(message)`
    GraphQL(String),
    /// Any other exception: shown as "Internal server error".
    Internal(String),
}

/// What a resolver is resolving.
#[derive(Debug)]
pub struct FieldInfo<'a> {
    /// The object type the field is on.
    pub parent_type: &'a str,
    /// The field name.
    pub field_name: &'a str,
    /// The field nodes, merged from the selections.
    pub field_nodes: &'a [&'a Field],
}

/// The application's resolvers.
pub trait Resolvers {
    /// Resolve a field; `None` uses the default resolver (dict lookup).
    fn resolve(
        &self,
        info: &FieldInfo<'_>,
        parent: &Value,
        args: &[(String, Value)],
    ) -> Option<Result<Value, ResolveError>>;

    /// `resolve_type` for an abstract type.
    fn resolve_type(
        &self,
        abstract_type: &str,
        value: &Value,
    ) -> Result<Option<String>, ResolveError>;
}

/// A source object: a resolver value or an introspection object.
#[derive(Debug, Clone)]
enum Src {
    V(Value),
    Schema,
    Type(TypeRef),
    Field(FieldRef),
    Input(InputSrc),
    EnumV(TypeId, usize),
    Directive(usize),
}

#[derive(Debug, Clone, Copy)]
enum InputSrc {
    FieldArg(FieldRef, usize),
    DirectiveArg(usize, usize),
    InputField(TypeId, usize),
}

/// A resolved (not yet completed) value.
#[derive(Debug, Clone)]
enum R {
    V(Value),
    S(Src),
    L(Vec<R>),
}

impl R {
    fn is_null(&self) -> bool {
        matches!(self, R::V(Value::Null))
    }
}

/// An error in flight, with whether it propagates (non-null).
type Raised = GraphQLError;

/// The result of an execution: `data` and `errors`.
#[derive(Debug)]
pub struct ExecutionResult {
    pub data: Option<Value>,
    pub errors: Vec<GraphQLError>,
}

pub(crate) struct Executor<'a> {
    schema: &'a Schema,
    coercer: Coercer<'a>,
    resolvers: &'a dyn Resolvers,
    fragments: HashMap<&'a str, &'a FragmentDefinition>,
    vars: Variables,
    errors: Vec<(GraphQLError, Option<Vec<PathSeg>>)>,
    nulled: Vec<Option<Vec<PathSeg>>>,
}

fn located(raw: GraphQLError, nodes: &[&Field], path: &[PathSeg]) -> GraphQLError {
    if raw.path.is_some() {
        return raw;
    }
    let positions = if raw.positions.is_empty() {
        nodes.iter().map(|n| n.pos).collect()
    } else {
        raw.positions
    };
    GraphQLError {
        message: raw.message,
        positions,
        path: Some(path.to_vec()),
        internal: raw.internal,
        extensions: raw.extensions,
    }
}

fn resolve_err(e: ResolveError) -> GraphQLError {
    match e {
        ResolveError::GraphQL(m) => GraphQLError::plain(m),
        ResolveError::Internal(m) => {
            let mut g = GraphQLError::plain(m);
            g.internal = true;
            g
        }
    }
}

fn internal(m: String) -> GraphQLError {
    let mut g = GraphQLError::plain(m);
    g.internal = true;
    g
}

/// `Executor.build()` then `execute_operation()`.
pub(crate) fn execute(
    schema: &Schema,
    scalars: &dyn ScalarParsers,
    resolvers: &dyn Resolvers,
    doc: &Document,
    operation_name: Option<&str>,
    raw_vars: Option<&Value>,
) -> ExecutionResult {
    let mut operation: Option<&OperationDefinition> = None;
    let mut fragments: HashMap<&str, &FragmentDefinition> = HashMap::new();
    for d in &doc.definitions {
        match d {
            Definition::Operation(o) => match operation_name {
                None => {
                    if operation.is_some() {
                        return ExecutionResult {
                            data: None,
                            errors: vec![GraphQLError::plain(
                                "Must provide operation name if query contains multiple operations.",
                            )],
                        };
                    }
                    operation = Some(o);
                }
                Some(n) => {
                    if o.name.as_ref().is_some_and(|x| x.value == n) {
                        operation = Some(o);
                    }
                }
            },
            Definition::Fragment(f) => {
                fragments.insert(&f.name.value, f);
            }
            Definition::TypeSystem(_) => {}
        }
    }
    let Some(op) = operation else {
        let msg = match operation_name {
            Some(n) => format!("Unknown operation named '{n}'."),
            None => "Must provide an operation.".to_owned(),
        };
        return ExecutionResult {
            data: None,
            errors: vec![GraphQLError::plain(msg)],
        };
    };
    let coercer = Coercer { schema, scalars };
    let empty = Value::Object(Vec::new());
    let inputs = raw_vars.unwrap_or(&empty);
    let vars = match coerce_variable_values(&coercer, &op.variable_definitions, inputs) {
        Ok(v) => v,
        Err(errors) => {
            return ExecutionResult { data: None, errors };
        }
    };
    let mut ex = Executor {
        schema,
        coercer,
        resolvers,
        fragments,
        vars,
        errors: Vec::new(),
        nulled: Vec::new(),
    };
    let Some(root) = schema.root_type(op.operation) else {
        return ExecutionResult {
            data: None,
            errors: vec![GraphQLError::new(
                format!(
                    "Schema is not configured to execute {} operation.",
                    op.operation.as_str()
                ),
                vec![op.pos],
            )],
        };
    };
    let groups = ex.collect_fields(root, &[&op.selection_set]);
    let data = match ex.execute_fields(root, &Src::V(Value::Null), &groups, &[]) {
        Ok(v) => Some(v),
        Err(e) => {
            ex.add_error(e, None);
            None
        }
    };
    ExecutionResult {
        data,
        errors: ex.errors.into_iter().map(|(e, _)| e).collect(),
    }
}

/// `coerce_variable_values()`
fn coerce_variable_values(
    coercer: &Coercer<'_>,
    defs: &[VariableDefinition],
    inputs: &Value,
) -> Result<Variables, Vec<GraphQLError>> {
    let mut errors: Vec<GraphQLError> = Vec::new();
    let mut coerced: Variables = HashMap::new();
    for d in defs {
        let name = &d.variable.name.value;
        let Some(t) = coercer.schema.type_from_ast(&d.type_) else {
            errors.push(GraphQLError::new(
                format!(
                    "Variable '${name}' expected value of type '{}' which cannot be used as an input type.",
                    crate::error::print_type(&d.type_)
                ),
                vec![d.type_.pos()],
            ));
            continue;
        };
        if !coercer.schema.t(t.named()).is_input() {
            errors.push(GraphQLError::new(
                format!(
                    "Variable '${name}' expected value of type '{}' which cannot be used as an input type.",
                    crate::error::print_type(&d.type_)
                ),
                vec![d.type_.pos()],
            ));
            continue;
        }
        let value = inputs.get(name);
        if value.is_none() {
            if let Some(dv) = &d.default_value {
                match coercer.input_literal(dv, &t, None) {
                    Some(v) => {
                        coerced.insert(name.clone(), v);
                    }
                    None => {
                        let mut path = Vec::new();
                        coercer.validate_input_literal(dv, &t, None, &mut path, &mut |e, p| {
                            errors.push(GraphQLError::new(
                                format!(
                                    "Variable '${name}' has invalid default value{}: {}",
                                    print_path_list(p),
                                    e.message
                                ),
                                vec![d.pos],
                            ));
                            true
                        });
                    }
                }
                continue;
            }
            if !t.is_non_null() {
                continue;
            }
        }
        match coercer.input_value(value, &t) {
            Some(v) => {
                coerced.insert(name.clone(), v);
            }
            None => {
                let mut path = Vec::new();
                coercer.validate_input_value(value, &t, &mut path, &mut |e, p| {
                    errors.push(GraphQLError::new(
                        format!(
                            "Variable '${name}' has invalid value{}: {}",
                            print_path_list(p),
                            e.message
                        ),
                        vec![d.pos],
                    ));
                });
            }
        }
    }
    if errors.is_empty() {
        Ok(coerced)
    } else {
        Err(errors)
    }
}

type Groups<'a> = Vec<(String, Vec<&'a Field>)>;

impl<'a> Executor<'a> {
    fn add_error(&mut self, e: GraphQLError, path: Option<Vec<PathSeg>>) {
        // `has_nulled_position()`
        let nulled = |p: &Option<Vec<PathSeg>>| -> bool {
            match p {
                None => self.nulled.iter().any(Option::is_none),
                Some(p) => {
                    (0..=p.len()).any(|n| self.nulled.iter().any(|x| x.as_deref() == Some(&p[..n])))
                        || self.nulled.iter().any(Option::is_none)
                }
            }
        };
        if nulled(&path) {
            return;
        }
        self.nulled.push(path.clone());
        self.errors.push((e, path));
    }

    fn should_include(&self, dirs: &[Directive]) -> bool {
        for d in dirs {
            let name = d.name.value.as_str();
            if name != "skip" && name != "include" {
                continue;
            }
            let Some(def) = self.schema.directive(name) else {
                continue;
            };
            let Ok(args) = get_argument_values(
                &self.coercer,
                &def.args,
                &d.arguments,
                d.pos,
                Some(&self.vars),
            ) else {
                continue;
            };
            let v = args
                .iter()
                .find(|(k, _)| k == "if")
                .map(|(_, v)| v.truthy())
                .unwrap_or(false);
            if (name == "skip" && v) || (name == "include" && !v) {
                return false;
            }
        }
        true
    }

    fn fragment_applies(&self, tc: Option<&NamedType>, t: TypeId) -> bool {
        let Some(tc) = tc else { return true };
        let Some(ct) = self.schema.type_id(&tc.name.value) else {
            return false;
        };
        if ct == t {
            return true;
        }
        self.schema.t(ct).is_abstract() && self.schema.is_sub_type(ct, t)
    }

    fn collect_fields(&self, t: TypeId, sets: &[&'a SelectionSet]) -> Groups<'a> {
        let mut out: Groups<'a> = Vec::new();
        let mut visited: Vec<&str> = Vec::new();
        for s in sets {
            self.collect_into(t, s, &mut out, &mut visited);
        }
        out
    }

    /// `collect_fields_impl()`, depth first through inline fragments and
    /// fragment spreads as graphql-core recurses, on an explicit stack.
    /// (Validation already ends chains of fragments far shorter than
    /// would matter here, but an explicit stack does not depend on it.)
    fn collect_into(
        &self,
        t: TypeId,
        set: &'a SelectionSet,
        out: &mut Groups<'a>,
        visited: &mut Vec<&'a str>,
    ) {
        let mut stack: Vec<std::slice::Iter<'a, Selection>> = vec![set.selections.iter()];
        while let Some(level) = stack.last_mut() {
            let Some(sel) = level.next() else {
                stack.pop();
                continue;
            };
            match sel {
                Selection::Field(f) => {
                    if !self.should_include(&f.directives) {
                        continue;
                    }
                    let k = f.response_key();
                    match out.iter_mut().find(|(x, _)| x == k) {
                        Some(e) => e.1.push(f),
                        None => out.push((k.to_owned(), vec![f])),
                    }
                }
                Selection::InlineFragment(i) => {
                    if !self.should_include(&i.directives)
                        || !self.fragment_applies(i.type_condition.as_ref(), t)
                    {
                        continue;
                    }
                    stack.push(i.selection_set.selections.iter());
                }
                Selection::FragmentSpread(fs) => {
                    let name = fs.name.value.as_str();
                    if visited.contains(&name) || !self.should_include(&fs.directives) {
                        continue;
                    }
                    visited.push(name);
                    let Some(f) = self.fragments.get(name) else {
                        continue;
                    };
                    if !self.fragment_applies(Some(&f.type_condition), t) {
                        continue;
                    }
                    stack.push(f.selection_set.selections.iter());
                }
            }
        }
    }

    fn execute_fields(
        &mut self,
        t: TypeId,
        src: &Src,
        groups: &Groups<'a>,
        path: &[PathSeg],
    ) -> Result<Value, Raised> {
        let mut out: Vec<(String, Value)> = Vec::new();
        for (key, nodes) in groups {
            let mut p = path.to_vec();
            p.push(PathSeg::Key(key.clone()));
            if let Some(v) = self.execute_field(t, src, nodes, &p)? {
                out.push((key.clone(), v));
            }
        }
        Ok(Value::Object(out))
    }

    /// `Ok(None)` when the field is not defined (it is left out).
    fn execute_field(
        &mut self,
        t: TypeId,
        src: &Src,
        nodes: &[&'a Field],
        path: &[PathSeg],
    ) -> Result<Option<Value>, Raised> {
        let first = nodes[0];
        let Some(fr) = self.schema.get_field(t, &first.name.value) else {
            return Ok(None);
        };
        let def = self.schema.field_def(fr);
        let return_type = def.type_.clone();
        let result = (|| -> Result<Value, GraphQLError> {
            let args = get_argument_values(
                &self.coercer,
                &def.args,
                &first.arguments,
                first.pos,
                Some(&self.vars),
            )?;
            let r = self.resolve(t, fr, src, nodes, &args)?;
            self.complete_value(&return_type, t, &first.name.value, nodes, path, r)
        })();
        match result {
            Ok(v) => Ok(Some(v)),
            Err(e) => {
                let e = located(e, nodes, path);
                if return_type.is_non_null() {
                    return Err(e);
                }
                self.add_error(e, Some(path.to_vec()));
                Ok(Some(Value::Null))
            }
        }
    }

    fn resolve(
        &self,
        t: TypeId,
        fr: FieldRef,
        src: &Src,
        nodes: &[&'a Field],
        args: &[(String, Value)],
    ) -> Result<R, GraphQLError> {
        let s = self.schema;
        let field_name = nodes[0].name.value.as_str();
        if let FieldRef::TypeNameMeta = fr {
            return Ok(R::V(Value::Str(s.t(t).name.clone())));
        }
        if let FieldRef::SchemaMeta = fr {
            return Ok(R::S(Src::Schema));
        }
        if let FieldRef::TypeMeta = fr {
            let name = args
                .iter()
                .find(|(k, _)| k == "name")
                .and_then(|(_, v)| v.as_str())
                .unwrap_or_default();
            return Ok(match s.type_id(name) {
                Some(id) => R::S(Src::Type(TypeRef::Named(id))),
                None => R::V(Value::Null),
            });
        }
        let include_deprecated = args
            .iter()
            .find(|(k, _)| k == "includeDeprecated")
            .is_some_and(|(_, v)| v.truthy());
        match src {
            Src::V(parent) => {
                let info = FieldInfo {
                    parent_type: &s.t(t).name,
                    field_name,
                    field_nodes: nodes,
                };
                match self.resolvers.resolve(&info, parent, args) {
                    Some(r) => r.map(R::V).map_err(resolve_err),
                    None => Ok(R::V(parent.get(field_name).cloned().unwrap_or(Value::Null))),
                }
            }
            Src::Schema => Ok(match field_name {
                "description" => R::V(Value::Null),
                "types" => R::L(
                    (0..s.types.len())
                        .map(|i| R::S(Src::Type(TypeRef::Named(i))))
                        .collect(),
                ),
                "queryType" => R::S(Src::Type(TypeRef::Named(s.query))),
                "mutationType" => s
                    .mutation
                    .map_or(R::V(Value::Null), |m| R::S(Src::Type(TypeRef::Named(m)))),
                "subscriptionType" => s
                    .subscription
                    .map_or(R::V(Value::Null), |m| R::S(Src::Type(TypeRef::Named(m)))),
                "directives" => R::L(
                    s.directives
                        .iter()
                        .enumerate()
                        .filter(|(_, d)| include_deprecated || d.deprecation_reason.is_none())
                        .map(|(i, _)| R::S(Src::Directive(i)))
                        .collect(),
                ),
                _ => R::V(Value::Null),
            }),
            Src::Type(tr) => Ok(self.resolve_type_field(tr, field_name, include_deprecated)),
            Src::Field(f) => {
                let d = s.field_def(*f);
                Ok(match field_name {
                    "name" => R::V(Value::Str(d.name.clone())),
                    "description" => R::V(opt_str(&d.description)),
                    "args" => R::L(
                        d.args
                            .iter()
                            .enumerate()
                            .filter(|(_, a)| include_deprecated || a.deprecation_reason.is_none())
                            .map(|(i, _)| R::S(Src::Input(InputSrc::FieldArg(*f, i))))
                            .collect(),
                    ),
                    "type" => R::S(Src::Type(d.type_.clone())),
                    "isDeprecated" => R::V(Value::Bool(d.deprecation_reason.is_some())),
                    "deprecationReason" => R::V(opt_str(&d.deprecation_reason)),
                    _ => R::V(Value::Null),
                })
            }
            Src::Input(i) => {
                let iv = match i {
                    InputSrc::FieldArg(f, n) => &s.field_def(*f).args[*n],
                    InputSrc::DirectiveArg(d, n) => &s.directives[*d].args[*n],
                    InputSrc::InputField(t, n) => &s.t(*t).input_fields[*n],
                };
                Ok(match field_name {
                    "name" => R::V(Value::Str(iv.name.clone())),
                    "description" => R::V(opt_str(&iv.description)),
                    "type" => R::S(Src::Type(iv.type_.clone())),
                    "defaultValue" => R::V(match &iv.default_value {
                        Some(d) => Value::Str(print_value(d)),
                        None => Value::Null,
                    }),
                    "isDeprecated" => R::V(Value::Bool(iv.deprecation_reason.is_some())),
                    "deprecationReason" => R::V(opt_str(&iv.deprecation_reason)),
                    _ => R::V(Value::Null),
                })
            }
            Src::EnumV(t, n) => {
                let ev = &s.t(*t).enum_values[*n];
                Ok(match field_name {
                    "name" => R::V(Value::Str(ev.name.clone())),
                    "description" => R::V(opt_str(&ev.description)),
                    "isDeprecated" => R::V(Value::Bool(ev.deprecation_reason.is_some())),
                    "deprecationReason" => R::V(opt_str(&ev.deprecation_reason)),
                    _ => R::V(Value::Null),
                })
            }
            Src::Directive(i) => {
                let d = &s.directives[*i];
                Ok(match field_name {
                    "name" => R::V(Value::Str(d.name.clone())),
                    "description" => R::V(opt_str(&d.description)),
                    "isRepeatable" => R::V(Value::Bool(d.repeatable)),
                    "locations" => R::L(
                        d.locations
                            .iter()
                            .map(|l| R::V(Value::Str(l.clone())))
                            .collect(),
                    ),
                    "args" => R::L(
                        d.args
                            .iter()
                            .enumerate()
                            .filter(|(_, a)| include_deprecated || a.deprecation_reason.is_none())
                            .map(|(n, _)| R::S(Src::Input(InputSrc::DirectiveArg(*i, n))))
                            .collect(),
                    ),
                    "isDeprecated" => R::V(Value::Bool(d.deprecation_reason.is_some())),
                    "deprecationReason" => R::V(opt_str(&d.deprecation_reason)),
                    _ => R::V(Value::Null),
                })
            }
        }
    }

    fn resolve_type_field(&self, tr: &TypeRef, field: &str, include_deprecated: bool) -> R {
        let s = self.schema;
        let null = R::V(Value::Null);
        match tr {
            TypeRef::List(inner) | TypeRef::NonNull(inner) => match field {
                "kind" => R::V(Value::str(if tr.is_list() { "LIST" } else { "NON_NULL" })),
                "ofType" => R::S(Src::Type((**inner).clone())),
                _ => null,
            },
            TypeRef::Named(id) => {
                let t = s.t(*id);
                match field {
                    "kind" => R::V(Value::str(match t.kind {
                        Kind::Scalar => "SCALAR",
                        Kind::Object => "OBJECT",
                        Kind::Interface => "INTERFACE",
                        Kind::Union => "UNION",
                        Kind::Enum => "ENUM",
                        Kind::InputObject => "INPUT_OBJECT",
                    })),
                    "name" => R::V(Value::Str(t.name.clone())),
                    "description" => R::V(opt_str(&t.description)),
                    "specifiedByURL" => R::V(opt_str(&t.specified_by_url)),
                    "fields" if matches!(t.kind, Kind::Object | Kind::Interface) => R::L(
                        t.fields
                            .iter()
                            .enumerate()
                            .filter(|(_, f)| include_deprecated || f.deprecation_reason.is_none())
                            .map(|(i, _)| R::S(Src::Field(FieldRef::Field(*id, i))))
                            .collect(),
                    ),
                    "interfaces" if matches!(t.kind, Kind::Object | Kind::Interface) => R::L(
                        t.interfaces
                            .iter()
                            .map(|i| R::S(Src::Type(TypeRef::Named(*i))))
                            .collect(),
                    ),
                    "possibleTypes" if t.is_abstract() => R::L(
                        s.possible_types(*id)
                            .iter()
                            .map(|i| R::S(Src::Type(TypeRef::Named(*i))))
                            .collect(),
                    ),
                    "enumValues" if t.kind == Kind::Enum => R::L(
                        t.enum_values
                            .iter()
                            .enumerate()
                            .filter(|(_, v)| include_deprecated || v.deprecation_reason.is_none())
                            .map(|(i, _)| R::S(Src::EnumV(*id, i)))
                            .collect(),
                    ),
                    "inputFields" if t.kind == Kind::InputObject => R::L(
                        t.input_fields
                            .iter()
                            .enumerate()
                            .filter(|(_, v)| include_deprecated || v.deprecation_reason.is_none())
                            .map(|(i, _)| R::S(Src::Input(InputSrc::InputField(*id, i))))
                            .collect(),
                    ),
                    "isOneOf" if t.kind == Kind::InputObject => R::V(Value::Bool(t.is_one_of)),
                    _ => null,
                }
            }
        }
    }

    fn complete_value(
        &mut self,
        t: &TypeRef,
        parent: TypeId,
        field_name: &str,
        nodes: &[&'a Field],
        path: &[PathSeg],
        r: R,
    ) -> Result<Value, GraphQLError> {
        if let TypeRef::NonNull(inner) = t {
            let v = self.complete_value(inner, parent, field_name, nodes, path, r)?;
            if v == Value::Null {
                return Err(internal(format!(
                    "Cannot return null for non-nullable field {}.{field_name}.",
                    self.schema.t(parent).name
                )));
            }
            return Ok(v);
        }
        if r.is_null() {
            return Ok(Value::Null);
        }
        if let TypeRef::List(item) = t {
            let items: Vec<R> = match r {
                R::L(items) => items,
                R::V(Value::List(items)) => items.into_iter().map(R::V).collect(),
                _ => {
                    return Err(GraphQLError::plain(format!(
                        "Expected Iterable, but did not find one for field '{}.{field_name}'.",
                        self.schema.t(parent).name
                    )));
                }
            };
            let mut out = Vec::with_capacity(items.len());
            for (i, it) in items.into_iter().enumerate() {
                let mut p = path.to_vec();
                p.push(PathSeg::Index(i));
                match self.complete_value(item, parent, field_name, nodes, &p, it) {
                    Ok(v) => out.push(v),
                    Err(e) => {
                        let e = located(e, nodes, &p);
                        if item.is_non_null() {
                            return Err(e);
                        }
                        self.add_error(e, Some(p));
                        out.push(Value::Null);
                    }
                }
            }
            return Ok(Value::List(out));
        }
        let id = t.named();
        let ty = self.schema.t(id);
        match ty.kind {
            Kind::Scalar | Kind::Enum => {
                let R::V(v) = r else {
                    return Err(internal("unexpected introspection value".into()));
                };
                self.serialize(id, &v)
            }
            Kind::Interface | Kind::Union => {
                let runtime = match &r {
                    R::V(v) => self
                        .resolvers
                        .resolve_type(&ty.name, v)
                        .map_err(resolve_err)?,
                    R::S(_) => None,
                    R::L(_) => None,
                };
                let parent_name = self.schema.t(parent).name.clone();
                let rt = match runtime {
                    None => {
                        return Err(GraphQLError::new(
                            format!(
                                "Abstract type '{}' must resolve to an Object type at runtime for field '{parent_name}.{field_name}'. Either the '{}' type should provide a 'resolve_type' function or each possible type should provide an 'is_type_of' function.",
                                ty.name, ty.name
                            ),
                            nodes.iter().map(|n| n.pos).collect(),
                        ));
                    }
                    Some(n) => n,
                };
                let Some(rid) = self.schema.type_id(&rt) else {
                    return Err(GraphQLError::new(
                        format!(
                            "Abstract type '{}' was resolved to a type '{rt}' that does not exist inside the schema.",
                            ty.name
                        ),
                        nodes.iter().map(|n| n.pos).collect(),
                    ));
                };
                if self.schema.t(rid).kind != Kind::Object {
                    return Err(GraphQLError::new(
                        format!(
                            "Abstract type '{}' was resolved to a non-object type '{rt}'.",
                            ty.name
                        ),
                        nodes.iter().map(|n| n.pos).collect(),
                    ));
                }
                if !self.schema.is_sub_type(id, rid) {
                    return Err(GraphQLError::new(
                        format!(
                            "Runtime Object type '{rt}' is not a possible type for '{}'.",
                            ty.name
                        ),
                        nodes.iter().map(|n| n.pos).collect(),
                    ));
                }
                self.complete_object(rid, nodes, path, r)
            }
            Kind::Object => self.complete_object(id, nodes, path, r),
            Kind::InputObject => Err(internal(format!(
                "Cannot complete value of unexpected output type: '{}'.",
                ty.name
            ))),
        }
    }

    fn complete_object(
        &mut self,
        id: TypeId,
        nodes: &[&'a Field],
        path: &[PathSeg],
        r: R,
    ) -> Result<Value, GraphQLError> {
        let src = match r {
            R::S(s) => s,
            R::V(v) => Src::V(v),
            R::L(_) => return Err(internal("unexpected list".into())),
        };
        let sets: Vec<&'a SelectionSet> = nodes
            .iter()
            .filter_map(|n| n.selection_set.as_ref())
            .collect();
        let groups = self.collect_fields(id, &sets);
        self.execute_fields(id, &src, &groups, path)
    }

    fn serialize(&self, id: TypeId, v: &Value) -> Result<Value, GraphQLError> {
        let t = self.schema.t(id);
        let g = |m: String| Err(GraphQLError::plain(m));
        if t.kind == Kind::Enum {
            if let Value::Str(s) = v
                && t.enum_values.iter().any(|e| e.name == *s)
            {
                return Ok(v.clone());
            }
            return g(format!(
                "Enum '{}' cannot represent value: {}",
                t.name,
                inspect(v)
            ));
        }
        match t.name.as_str() {
            "String" => match v {
                Value::Str(_) => Ok(v.clone()),
                Value::Bool(b) => Ok(Value::str(if *b { "true" } else { "false" })),
                Value::Int(i) => Ok(Value::Str(i.to_string())),
                Value::BigInt(s) => Ok(Value::Str(s.clone())),
                Value::Float(f) if f.is_finite() => Ok(Value::Str(float_repr(*f))),
                _ => g(format!("String cannot represent value: {}", inspect(v))),
            },
            "Int" => match v {
                Value::Bool(b) => Ok(Value::Int(i128::from(*b))),
                Value::Int(i) if (-2_147_483_648..=2_147_483_647).contains(i) => Ok(v.clone()),
                Value::Int(_) | Value::BigInt(_) => g(format!(
                    "Int cannot represent non 32-bit signed integer value: {}",
                    inspect(v)
                )),
                Value::Float(f) if f.is_finite() && f.trunc() == *f => {
                    if (-2_147_483_648.0..=2_147_483_647.0).contains(f) {
                        Ok(Value::Int(*f as i128))
                    } else {
                        g(format!(
                            "Int cannot represent non 32-bit signed integer value: {}",
                            inspect(v)
                        ))
                    }
                }
                Value::Str(s) => match s.trim().parse::<i128>() {
                    Ok(i) if (-2_147_483_648..=2_147_483_647).contains(&i) => Ok(Value::Int(i)),
                    Ok(_) => g(format!(
                        "Int cannot represent non 32-bit signed integer value: {}",
                        inspect(v)
                    )),
                    Err(_) => g(format!(
                        "Int cannot represent non-integer value: {}",
                        inspect(v)
                    )),
                },
                _ => g(format!(
                    "Int cannot represent non-integer value: {}",
                    inspect(v)
                )),
            },
            "Boolean" => match v {
                Value::Bool(_) => Ok(v.clone()),
                Value::Int(i) => Ok(Value::Bool(*i != 0)),
                Value::Float(f) if f.is_finite() => Ok(Value::Bool(*f != 0.0)),
                _ => g(format!(
                    "Boolean cannot represent a non boolean value: {}",
                    inspect(v)
                )),
            },
            "Float" => match v {
                Value::Bool(b) => Ok(Value::Int(i128::from(*b))),
                Value::Float(f) if f.is_finite() => Ok(v.clone()),
                Value::Int(i) => Ok(Value::Float(*i as f64)),
                _ => g(format!(
                    "Float cannot represent non numeric value: {}",
                    inspect(v)
                )),
            },
            "ID" => match v {
                Value::Str(_) => Ok(v.clone()),
                Value::Int(i) => Ok(Value::Str(i.to_string())),
                _ => g(format!("ID cannot represent value: {}", inspect(v))),
            },
            // Custom scalars serialize as they are.
            _ => Ok(v.clone()),
        }
    }
}

fn opt_str(s: &Option<String>) -> Value {
    match s {
        Some(s) => Value::Str(s.clone()),
        None => Value::Null,
    }
}
