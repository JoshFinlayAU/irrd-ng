//! The type system: a schema built from SDL the way graphql-core's
//! `build_ast_schema()` builds one, with the type map in graphql-core's
//! order (which introspection exposes).

use std::collections::HashMap;

use crate::ast::{self, Definition, TypeSystemKind, ValueNode};
use crate::parser;

/// Index into [`Schema::types`].
pub type TypeId = usize;

/// A type reference: named, list or non-null.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeRef {
    /// A named type.
    Named(TypeId),
    /// `[T]`
    List(Box<TypeRef>),
    /// `T!`
    NonNull(Box<TypeRef>),
}

impl TypeRef {
    /// `get_named_type()`
    pub fn named(&self) -> TypeId {
        match self {
            TypeRef::Named(t) => *t,
            TypeRef::List(i) | TypeRef::NonNull(i) => i.named(),
        }
    }

    /// `get_nullable_type()`
    pub fn nullable(&self) -> &TypeRef {
        match self {
            TypeRef::NonNull(i) => i,
            t => t,
        }
    }

    /// Whether this is `T!`.
    pub fn is_non_null(&self) -> bool {
        matches!(self, TypeRef::NonNull(_))
    }

    /// Whether this is a list (not under a non-null).
    pub fn is_list(&self) -> bool {
        matches!(self, TypeRef::List(_))
    }
}

/// The kind of a named type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Scalar,
    Object,
    Interface,
    Union,
    Enum,
    InputObject,
}

/// An argument or input field.
#[derive(Debug, Clone)]
pub struct InputValue {
    pub name: String,
    pub description: Option<String>,
    pub type_: TypeRef,
    /// The default as written in the SDL.
    pub default_value: Option<ValueNode>,
    pub deprecation_reason: Option<String>,
}

/// An output field.
#[derive(Debug, Clone)]
pub struct FieldDef {
    pub name: String,
    pub description: Option<String>,
    pub args: Vec<InputValue>,
    pub type_: TypeRef,
    pub deprecation_reason: Option<String>,
}

/// An enum value.
#[derive(Debug, Clone)]
pub struct EnumValue {
    pub name: String,
    pub description: Option<String>,
    pub deprecation_reason: Option<String>,
}

/// A named type.
#[derive(Debug, Clone)]
pub struct NamedType {
    pub name: String,
    pub kind: Kind,
    pub description: Option<String>,
    pub fields: Vec<FieldDef>,
    pub interfaces: Vec<TypeId>,
    /// Union members in declared order, or objects implementing an
    /// interface in type map order.
    pub possible: Vec<TypeId>,
    pub enum_values: Vec<EnumValue>,
    pub input_fields: Vec<InputValue>,
    pub specified_by_url: Option<String>,
    pub is_one_of: bool,
}

impl NamedType {
    /// A field by name.
    pub fn field(&self, name: &str) -> Option<&FieldDef> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Scalar or enum.
    pub fn is_leaf(&self) -> bool {
        matches!(self.kind, Kind::Scalar | Kind::Enum)
    }

    /// Object, interface or union.
    pub fn is_composite(&self) -> bool {
        matches!(self.kind, Kind::Object | Kind::Interface | Kind::Union)
    }

    /// Interface or union.
    pub fn is_abstract(&self) -> bool {
        matches!(self.kind, Kind::Interface | Kind::Union)
    }

    /// Scalar, enum or input object.
    pub fn is_input(&self) -> bool {
        matches!(self.kind, Kind::Scalar | Kind::Enum | Kind::InputObject)
    }

    /// Object, interface, union, scalar or enum.
    pub fn is_output(&self) -> bool {
        !matches!(self.kind, Kind::InputObject)
    }
}

/// A directive definition.
#[derive(Debug, Clone)]
pub struct DirectiveDef {
    pub name: String,
    pub description: Option<String>,
    pub args: Vec<InputValue>,
    pub locations: Vec<String>,
    pub repeatable: bool,
    pub deprecation_reason: Option<String>,
}

/// A built schema.
#[derive(Debug, Clone)]
pub struct Schema {
    pub types: Vec<NamedType>,
    by_name: HashMap<String, TypeId>,
    pub query: TypeId,
    pub mutation: Option<TypeId>,
    pub subscription: Option<TypeId>,
    pub directives: Vec<DirectiveDef>,
    /// Interfaces implementing each interface (for `is_sub_type`).
    interface_impls: HashMap<TypeId, Vec<TypeId>>,
    /// `__schema`, `__type` and `__typename`.
    pub schema_meta: FieldDef,
    pub type_meta: FieldDef,
    pub typename_meta: FieldDef,
}

/// A field definition found by `get_field()`.
#[derive(Debug, Clone, Copy)]
pub enum FieldRef {
    /// `fields[index]` of a type.
    Field(TypeId, usize),
    /// `__schema`
    SchemaMeta,
    /// `__type`
    TypeMeta,
    /// `__typename`
    TypeNameMeta,
}

const BUILTINS: &str = include_str!("builtins.graphql");

/// Names of the built-in scalars.
pub const SPECIFIED_SCALARS: &[&str] = &["String", "Int", "Float", "Boolean", "ID"];
/// Names of the introspection types.
pub const INTROSPECTION_TYPES: &[&str] = &[
    "__Schema",
    "__Type",
    "__TypeKind",
    "__Field",
    "__InputValue",
    "__EnumValue",
    "__Directive",
    "__DirectiveLocation",
];

struct Pending {
    def: ast::TypeSystemDefinition,
}

impl Schema {
    /// `build_schema(sdl)` for a schema without custom directives.
    /// Panics on a malformed SDL: the schema is a compile-time constant.
    pub fn from_sdl(sdl: &str) -> Schema {
        let builtin_chars: Vec<char> = BUILTINS.chars().collect();
        let builtin_doc = parser::parse(&builtin_chars).expect("built-in SDL");
        let chars: Vec<char> = sdl.chars().collect();
        let doc = parser::parse(&chars).expect("schema SDL");

        // Every definition by name: the document's first, then the
        // built-ins it does not define.
        let mut defs: Vec<Pending> = Vec::new();
        let mut user_order: Vec<String> = Vec::new();
        let mut schema_ops: Vec<(ast::OperationType, String)> = Vec::new();
        for d in &doc.definitions {
            if let Definition::TypeSystem(t) = d {
                if t.kind == TypeSystemKind::SchemaDefinition {
                    for (op, nt) in &t.operation_types {
                        schema_ops.push((*op, nt.name.value.clone()));
                    }
                    continue;
                }
                if t.kind.is_type_definition() {
                    user_order.push(t.name.as_ref().map(|n| n.value.clone()).unwrap_or_default());
                    defs.push(Pending { def: t.clone() });
                }
            }
        }
        let mut directive_defs: Vec<ast::TypeSystemDefinition> = Vec::new();
        for d in &builtin_doc.definitions {
            if let Definition::TypeSystem(t) = d {
                if t.kind == TypeSystemKind::DirectiveDefinition {
                    directive_defs.push(t.clone());
                } else if t.kind.is_type_definition() {
                    let name = t.name.as_ref().map(|n| n.value.clone()).unwrap_or_default();
                    if !user_order.contains(&name) {
                        defs.push(Pending { def: t.clone() });
                    }
                }
            }
        }
        let index: HashMap<String, usize> = defs
            .iter()
            .enumerate()
            .map(|(i, p)| (p.def.name.as_ref().map(|n| n.value.clone()).unwrap_or_default(), i))
            .collect();

        // graphql-core's TypeSet: every document type is removed and
        // re-collected in order, which appends the types it references
        // and has not seen yet right after it.
        let mut order: Vec<usize> = Vec::new();
        let mut seen = vec![false; defs.len()];
        fn collect(
            i: usize,
            defs: &[Pending],
            index: &HashMap<String, usize>,
            seen: &mut Vec<bool>,
            order: &mut Vec<usize>,
        ) {
            if seen[i] {
                return;
            }
            seen[i] = true;
            order.push(i);
            let d = &defs[i].def;
            let mut refs: Vec<&str> = Vec::new();
            fn named(t: &ast::Type) -> &str {
                match t {
                    ast::Type::Named(n) => &n.name.value,
                    ast::Type::List(_, i) | ast::Type::NonNull(_, i) => named(i),
                }
            }
            match d.kind {
                TypeSystemKind::UnionTypeDefinition => {
                    refs.extend(d.types.iter().map(|t| t.name.value.as_str()));
                }
                TypeSystemKind::ObjectTypeDefinition | TypeSystemKind::InterfaceTypeDefinition => {
                    refs.extend(d.interfaces.iter().map(|t| t.name.value.as_str()));
                    for f in &d.fields {
                        refs.push(named(&f.type_));
                        for a in &f.arguments {
                            refs.push(named(&a.type_));
                        }
                    }
                }
                TypeSystemKind::InputObjectTypeDefinition => {
                    for f in &d.fields {
                        refs.push(named(&f.type_));
                    }
                }
                _ => {}
            }
            // The recursion follows Python's: each reference is
            // collected fully before the next.
            for r in refs {
                if let Some(&j) = index.get(r) {
                    collect(j, defs, index, seen, order);
                }
            }
        }
        // Initially every document type counts as present.
        for name in &user_order {
            if let Some(&i) = index.get(name) {
                seen[i] = true;
            }
        }
        for name in &user_order {
            if let Some(&i) = index.get(name) {
                seen[i] = false;
                collect(i, &defs, &index, &mut seen, &mut order);
            }
        }
        let query_name = schema_ops
            .iter()
            .find(|(op, _)| *op == ast::OperationType::Query)
            .map(|(_, n)| n.clone())
            .unwrap_or_else(|| "Query".to_owned());
        if let Some(&q) = index.get(&query_name) {
            collect(q, &defs, &index, &mut seen, &mut order);
        }
        for dd in &directive_defs {
            for a in &dd.arguments {
                fn named(t: &ast::Type) -> &str {
                    match t {
                        ast::Type::Named(n) => &n.name.value,
                        ast::Type::List(_, i) | ast::Type::NonNull(_, i) => named(i),
                    }
                }
                if let Some(&j) = index.get(named(&a.type_)) {
                    collect(j, &defs, &index, &mut seen, &mut order);
                }
            }
        }
        if let Some(&s) = index.get("__Schema") {
            collect(s, &defs, &index, &mut seen, &mut order);
        }

        // Ids follow the final order.
        let mut by_name: HashMap<String, TypeId> = HashMap::new();
        for (id, &i) in order.iter().enumerate() {
            let name = defs[i].def.name.as_ref().map(|n| n.value.clone()).unwrap_or_default();
            by_name.insert(name, id);
        }
        let resolve = |t: &ast::Type| -> TypeRef {
            fn go(t: &ast::Type, by_name: &HashMap<String, TypeId>) -> TypeRef {
                match t {
                    ast::Type::Named(n) => TypeRef::Named(
                        by_name.get(&n.name.value).copied().unwrap_or_else(|| {
                            panic!("unknown type {} in SDL", n.name.value)
                        }),
                    ),
                    ast::Type::List(_, i) => TypeRef::List(Box::new(go(i, by_name))),
                    ast::Type::NonNull(_, i) => TypeRef::NonNull(Box::new(go(i, by_name))),
                }
            }
            go(t, &by_name)
        };
        let deprecation = |dirs: &[ast::Directive]| -> Option<String> {
            dirs.iter().find(|d| d.name.value == "deprecated").map(|d| {
                d.arguments
                    .iter()
                    .find(|a| a.name.value == "reason")
                    .and_then(|a| match &a.value {
                        ValueNode::String(_, s, _) => Some(s.clone()),
                        _ => None,
                    })
                    .unwrap_or_else(|| "No longer supported".to_owned())
            })
        };
        let input_value = |a: &ast::InputValueDefinition| InputValue {
            name: a.name.value.clone(),
            description: a.description.clone(),
            type_: resolve(&a.type_),
            default_value: a.default_value.clone(),
            deprecation_reason: deprecation(&a.directives),
        };

        let mut types: Vec<NamedType> = Vec::new();
        for &i in &order {
            let d = &defs[i].def;
            let kind = match d.kind {
                TypeSystemKind::ScalarTypeDefinition => Kind::Scalar,
                TypeSystemKind::ObjectTypeDefinition => Kind::Object,
                TypeSystemKind::InterfaceTypeDefinition => Kind::Interface,
                TypeSystemKind::UnionTypeDefinition => Kind::Union,
                TypeSystemKind::EnumTypeDefinition => Kind::Enum,
                _ => Kind::InputObject,
            };
            let fields = if matches!(kind, Kind::Object | Kind::Interface) {
                d.fields
                    .iter()
                    .map(|f| FieldDef {
                        name: f.name.value.clone(),
                        description: f.description.clone(),
                        args: f.arguments.iter().map(input_value).collect(),
                        type_: resolve(&f.type_),
                        deprecation_reason: deprecation(&f.directives),
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let input_fields = if kind == Kind::InputObject {
                d.fields
                    .iter()
                    .map(|f| InputValue {
                        name: f.name.value.clone(),
                        description: f.description.clone(),
                        type_: resolve(&f.type_),
                        default_value: f.default_value.clone(),
                        deprecation_reason: deprecation(&f.directives),
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let specified_by_url = d
                .directives
                .iter()
                .find(|x| x.name.value == "specifiedBy")
                .and_then(|x| x.arguments.first())
                .and_then(|a| match &a.value {
                    ValueNode::String(_, s, _) => Some(s.clone()),
                    _ => None,
                });
            types.push(NamedType {
                name: d.name.as_ref().map(|n| n.value.clone()).unwrap_or_default(),
                kind,
                description: d.description.clone(),
                fields,
                interfaces: d
                    .interfaces
                    .iter()
                    .filter_map(|n| by_name.get(&n.name.value).copied())
                    .collect(),
                possible: d
                    .types
                    .iter()
                    .filter_map(|n| by_name.get(&n.name.value).copied())
                    .collect(),
                enum_values: d
                    .values
                    .iter()
                    .map(|v| EnumValue {
                        name: v.name.value.clone(),
                        description: v.description.clone(),
                        deprecation_reason: deprecation(&v.directives),
                    })
                    .collect(),
                input_fields,
                specified_by_url,
                is_one_of: d.directives.iter().any(|x| x.name.value == "oneOf"),
            });
        }
        // Objects implementing each interface, in type map order.
        let mut interface_impls: HashMap<TypeId, Vec<TypeId>> = HashMap::new();
        let n = types.len();
        for id in 0..n {
            let ifaces = types[id].interfaces.clone();
            match types[id].kind {
                Kind::Object => {
                    for i in ifaces {
                        types[i].possible.push(id);
                    }
                }
                Kind::Interface => {
                    for i in ifaces {
                        interface_impls.entry(i).or_default().push(id);
                    }
                }
                _ => {}
            }
        }
        let directives = directive_defs
            .iter()
            .map(|d| DirectiveDef {
                name: d.name.as_ref().map(|n| n.value.clone()).unwrap_or_default(),
                description: d.description.clone(),
                args: d.arguments.iter().map(input_value).collect(),
                locations: d.locations.iter().map(|l| l.value.clone()).collect(),
                repeatable: d.repeatable,
                deprecation_reason: deprecation(&d.directives),
            })
            .collect();
        let op_type = |op: ast::OperationType, default: &str| -> Option<TypeId> {
            let name = schema_ops
                .iter()
                .find(|(o, _)| *o == op)
                .map(|(_, n)| n.clone())
                .unwrap_or_else(|| default.to_owned());
            by_name.get(&name).copied()
        };
        let id = |n: &str| by_name.get(n).copied().expect("built-in type");
        let schema_meta = FieldDef {
            name: "__schema".into(),
            description: Some("Access the current type schema of this server.".into()),
            args: Vec::new(),
            type_: TypeRef::NonNull(Box::new(TypeRef::Named(id("__Schema")))),
            deprecation_reason: None,
        };
        let type_meta = FieldDef {
            name: "__type".into(),
            description: Some("Request the type information of a single type.".into()),
            args: vec![InputValue {
                name: "name".into(),
                description: None,
                type_: TypeRef::NonNull(Box::new(TypeRef::Named(id("String")))),
                default_value: None,
                deprecation_reason: None,
            }],
            type_: TypeRef::Named(id("__Type")),
            deprecation_reason: None,
        };
        let typename_meta = FieldDef {
            name: "__typename".into(),
            description: Some("The name of the current Object type at runtime.".into()),
            args: Vec::new(),
            type_: TypeRef::NonNull(Box::new(TypeRef::Named(id("String")))),
            deprecation_reason: None,
        };
        Schema {
            schema_meta,
            type_meta,
            typename_meta,
            query: by_name.get(&query_name).copied().expect("query type"),
            mutation: op_type(ast::OperationType::Mutation, "Mutation"),
            subscription: op_type(ast::OperationType::Subscription, "Subscription"),
            types,
            by_name,
            directives,
            interface_impls,
        }
    }

    /// A type by name.
    pub fn type_id(&self, name: &str) -> Option<TypeId> {
        self.by_name.get(name).copied()
    }

    /// The named type.
    pub fn t(&self, id: TypeId) -> &NamedType {
        &self.types[id]
    }

    /// `get_root_type()`
    pub fn root_type(&self, op: ast::OperationType) -> Option<TypeId> {
        match op {
            ast::OperationType::Query => Some(self.query),
            ast::OperationType::Mutation => self.mutation,
            ast::OperationType::Subscription => self.subscription,
        }
    }

    /// A directive by name.
    pub fn directive(&self, name: &str) -> Option<&DirectiveDef> {
        self.directives.iter().find(|d| d.name == name)
    }

    /// `get_possible_types()`
    pub fn possible_types(&self, abstract_: TypeId) -> &[TypeId] {
        &self.types[abstract_].possible
    }

    /// `is_sub_type(abstract, maybe_sub)`
    pub fn is_sub_type(&self, abstract_: TypeId, maybe_sub: TypeId) -> bool {
        match self.types[abstract_].kind {
            Kind::Union => self.types[abstract_].possible.contains(&maybe_sub),
            Kind::Interface => {
                self.types[abstract_].possible.contains(&maybe_sub)
                    || self
                        .interface_impls
                        .get(&abstract_)
                        .is_some_and(|v| v.contains(&maybe_sub))
            }
            _ => false,
        }
    }

    /// `str(type)`: `[String!]`.
    pub fn type_str(&self, t: &TypeRef) -> String {
        match t {
            TypeRef::Named(id) => self.types[*id].name.clone(),
            TypeRef::List(i) => format!("[{}]", self.type_str(i)),
            TypeRef::NonNull(i) => format!("{}!", self.type_str(i)),
        }
    }

    /// `type_from_ast()`: `None` when a name is unknown.
    pub fn type_from_ast(&self, t: &ast::Type) -> Option<TypeRef> {
        match t {
            ast::Type::Named(n) => self.type_id(&n.name.value).map(TypeRef::Named),
            ast::Type::List(_, i) => Some(TypeRef::List(Box::new(self.type_from_ast(i)?))),
            ast::Type::NonNull(_, i) => Some(TypeRef::NonNull(Box::new(self.type_from_ast(i)?))),
        }
    }

    /// `is_type_sub_type_of()`
    pub fn is_type_sub_type_of(&self, maybe_sub: &TypeRef, super_: &TypeRef) -> bool {
        if maybe_sub == super_ {
            return true;
        }
        if let TypeRef::NonNull(s) = super_ {
            if let TypeRef::NonNull(m) = maybe_sub {
                return self.is_type_sub_type_of(m, s);
            }
            return false;
        }
        if let TypeRef::NonNull(m) = maybe_sub {
            return self.is_type_sub_type_of(m, super_);
        }
        if let TypeRef::List(s) = super_ {
            if let TypeRef::List(m) = maybe_sub {
                return self.is_type_sub_type_of(m, s);
            }
            return false;
        }
        if let TypeRef::List(_) = maybe_sub {
            return false;
        }
        let (TypeRef::Named(a), TypeRef::Named(b)) = (maybe_sub, super_) else {
            return false;
        };
        self.types[*b].is_abstract()
            && matches!(self.types[*a].kind, Kind::Interface | Kind::Object)
            && self.is_sub_type(*b, *a)
    }

    /// `do_types_overlap()`
    pub fn do_types_overlap(&self, a: TypeId, b: TypeId) -> bool {
        if a == b {
            return true;
        }
        let ta = &self.types[a];
        let tb = &self.types[b];
        if ta.is_abstract() {
            if tb.is_abstract() {
                return self
                    .possible_types(a)
                    .iter()
                    .any(|t| self.is_sub_type(b, *t));
            }
            return self.is_sub_type(a, b);
        }
        if tb.is_abstract() {
            return self.is_sub_type(b, a);
        }
        false
    }

    /// `get_field()`, including the meta fields.
    pub fn get_field(&self, parent: TypeId, name: &str) -> Option<FieldRef> {
        if name == "__schema" && parent == self.query {
            return Some(FieldRef::SchemaMeta);
        }
        if name == "__type" && parent == self.query {
            return Some(FieldRef::TypeMeta);
        }
        if name == "__typename" {
            return Some(FieldRef::TypeNameMeta);
        }
        let t = &self.types[parent];
        if !matches!(t.kind, Kind::Object | Kind::Interface) {
            return None;
        }
        t.fields
            .iter()
            .position(|f| f.name == name)
            .map(|i| FieldRef::Field(parent, i))
    }

    /// The definition a [`FieldRef`] names.
    pub fn field_def(&self, f: FieldRef) -> &FieldDef {
        match f {
            FieldRef::Field(t, i) => &self.types[t].fields[i],
            FieldRef::SchemaMeta => &self.schema_meta,
            FieldRef::TypeMeta => &self.type_meta,
            FieldRef::TypeNameMeta => &self.typename_meta,
        }
    }

    /// Fields of an object or interface type (empty for others).
    pub fn fields_of(&self, id: TypeId) -> &[FieldDef] {
        &self.types[id].fields
    }
}
