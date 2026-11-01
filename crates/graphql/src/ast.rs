//! The GraphQL AST, as graphql-core's `language.ast` defines it. Every
//! node keeps the character offset where it starts (`pos`), which is all
//! error locations need.

/// `OperationType`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    /// `query`
    Query,
    /// `mutation`
    Mutation,
    /// `subscription`
    Subscription,
}

impl OperationType {
    /// `operation.value`
    pub fn as_str(self) -> &'static str {
        match self {
            OperationType::Query => "query",
            OperationType::Mutation => "mutation",
            OperationType::Subscription => "subscription",
        }
    }
}

/// `NameNode`
#[derive(Debug, Clone)]
pub struct Name {
    pub pos: usize,
    pub value: String,
}

/// `DocumentNode`
#[derive(Debug, Clone)]
pub struct Document {
    pub definitions: Vec<Definition>,
}

/// A top-level definition.
#[derive(Debug, Clone)]
pub enum Definition {
    Operation(OperationDefinition),
    Fragment(FragmentDefinition),
    /// Any type system definition or extension. Only its kind, name,
    /// position and the parts validation visits are kept.
    TypeSystem(TypeSystemDefinition),
}

/// `OperationDefinitionNode`
#[derive(Debug, Clone)]
pub struct OperationDefinition {
    pub pos: usize,
    pub operation: OperationType,
    pub name: Option<Name>,
    pub variable_definitions: Vec<VariableDefinition>,
    pub directives: Vec<Directive>,
    pub selection_set: SelectionSet,
}

/// `FragmentDefinitionNode`
#[derive(Debug, Clone)]
pub struct FragmentDefinition {
    pub pos: usize,
    pub name: Name,
    pub type_condition: NamedType,
    pub directives: Vec<Directive>,
    pub selection_set: SelectionSet,
}

/// `VariableDefinitionNode`
#[derive(Debug, Clone)]
pub struct VariableDefinition {
    pub pos: usize,
    pub variable: Variable,
    pub type_: Type,
    pub default_value: Option<ValueNode>,
    pub directives: Vec<Directive>,
}

/// `VariableNode`
#[derive(Debug, Clone)]
pub struct Variable {
    pub pos: usize,
    pub name: Name,
}

/// `SelectionSetNode`
#[derive(Debug, Clone)]
pub struct SelectionSet {
    pub pos: usize,
    pub selections: Vec<Selection>,
}

/// `SelectionNode`
#[derive(Debug, Clone)]
pub enum Selection {
    Field(Field),
    FragmentSpread(FragmentSpread),
    InlineFragment(InlineFragment),
}

impl Selection {
    /// The selection's directives.
    pub fn directives(&self) -> &[Directive] {
        match self {
            Selection::Field(f) => &f.directives,
            Selection::FragmentSpread(f) => &f.directives,
            Selection::InlineFragment(f) => &f.directives,
        }
    }
}

/// `FieldNode`
#[derive(Debug, Clone)]
pub struct Field {
    pub pos: usize,
    pub alias: Option<Name>,
    pub name: Name,
    pub arguments: Vec<Argument>,
    pub directives: Vec<Directive>,
    pub selection_set: Option<SelectionSet>,
}

impl Field {
    /// The response key: the alias or the name.
    pub fn response_key(&self) -> &str {
        self.alias.as_ref().unwrap_or(&self.name).value.as_str()
    }
}

/// `FragmentSpreadNode`
#[derive(Debug, Clone)]
pub struct FragmentSpread {
    pub pos: usize,
    pub name: Name,
    pub directives: Vec<Directive>,
}

/// `InlineFragmentNode`
#[derive(Debug, Clone)]
pub struct InlineFragment {
    pub pos: usize,
    pub type_condition: Option<NamedType>,
    pub directives: Vec<Directive>,
    pub selection_set: SelectionSet,
}

/// `ArgumentNode`
#[derive(Debug, Clone)]
pub struct Argument {
    pub pos: usize,
    pub name: Name,
    pub value: ValueNode,
}

/// `DirectiveNode`
#[derive(Debug, Clone)]
pub struct Directive {
    pub pos: usize,
    pub name: Name,
    pub arguments: Vec<Argument>,
}

/// `TypeNode`
#[derive(Debug, Clone)]
pub enum Type {
    Named(NamedType),
    List(usize, Box<Type>),
    NonNull(usize, Box<Type>),
}

impl Type {
    /// Where the node starts.
    pub fn pos(&self) -> usize {
        match self {
            Type::Named(n) => n.pos,
            Type::List(p, _) | Type::NonNull(p, _) => *p,
        }
    }
}

/// `NamedTypeNode`
#[derive(Debug, Clone)]
pub struct NamedType {
    pub pos: usize,
    pub name: Name,
}

/// `ValueNode`
#[derive(Debug, Clone)]
pub enum ValueNode {
    Variable(Variable),
    Int(usize, String),
    Float(usize, String),
    String(usize, String, bool),
    Boolean(usize, bool),
    Null(usize),
    Enum(usize, String),
    List(usize, Vec<ValueNode>),
    Object(usize, Vec<ObjectField>),
}

impl ValueNode {
    /// Where the node starts.
    pub fn pos(&self) -> usize {
        match self {
            ValueNode::Variable(v) => v.pos,
            ValueNode::Int(p, _)
            | ValueNode::Float(p, _)
            | ValueNode::String(p, _, _)
            | ValueNode::Boolean(p, _)
            | ValueNode::Null(p)
            | ValueNode::Enum(p, _)
            | ValueNode::List(p, _)
            | ValueNode::Object(p, _) => *p,
        }
    }
}

/// `ObjectFieldNode`
#[derive(Debug, Clone)]
pub struct ObjectField {
    pub pos: usize,
    pub name: Name,
    pub value: ValueNode,
}

/// The kind of a type system definition or extension, as graphql-core
/// names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeSystemKind {
    SchemaDefinition,
    SchemaExtension,
    ScalarTypeDefinition,
    ObjectTypeDefinition,
    InterfaceTypeDefinition,
    UnionTypeDefinition,
    EnumTypeDefinition,
    InputObjectTypeDefinition,
    DirectiveDefinition,
    ScalarTypeExtension,
    ObjectTypeExtension,
    InterfaceTypeExtension,
    UnionTypeExtension,
    EnumTypeExtension,
    InputObjectTypeExtension,
    DirectiveExtension,
}

impl TypeSystemKind {
    /// A type definition (not an extension, schema or directive).
    pub fn is_type_definition(self) -> bool {
        matches!(
            self,
            TypeSystemKind::ScalarTypeDefinition
                | TypeSystemKind::ObjectTypeDefinition
                | TypeSystemKind::InterfaceTypeDefinition
                | TypeSystemKind::UnionTypeDefinition
                | TypeSystemKind::EnumTypeDefinition
                | TypeSystemKind::InputObjectTypeDefinition
        )
    }

    /// A type extension.
    pub fn is_type_extension(self) -> bool {
        matches!(
            self,
            TypeSystemKind::ScalarTypeExtension
                | TypeSystemKind::ObjectTypeExtension
                | TypeSystemKind::InterfaceTypeExtension
                | TypeSystemKind::UnionTypeExtension
                | TypeSystemKind::EnumTypeExtension
                | TypeSystemKind::InputObjectTypeExtension
        )
    }
}

/// A type system definition or extension. The parser keeps everything
/// that building a schema from SDL needs.
#[derive(Debug, Clone)]
pub struct TypeSystemDefinition {
    pub pos: usize,
    pub kind: TypeSystemKind,
    pub description: Option<String>,
    /// `None` for schema definitions and extensions.
    pub name: Option<Name>,
    pub directives: Vec<Directive>,
    /// Object and interface fields, and input object fields (as fields
    /// without arguments).
    pub fields: Vec<FieldDefinition>,
    /// `implements` for objects and interfaces.
    pub interfaces: Vec<NamedType>,
    /// Union members.
    pub types: Vec<NamedType>,
    /// Enum values.
    pub values: Vec<EnumValueDefinition>,
    /// Directive definition arguments.
    pub arguments: Vec<InputValueDefinition>,
    /// Directive definition locations.
    pub locations: Vec<Name>,
    /// Directive definition `repeatable`.
    pub repeatable: bool,
    /// Schema operation types.
    pub operation_types: Vec<(OperationType, NamedType)>,
}

/// `FieldDefinitionNode` (and, for input objects, `InputValueDefinitionNode`).
#[derive(Debug, Clone)]
pub struct FieldDefinition {
    pub pos: usize,
    pub description: Option<String>,
    pub name: Name,
    pub arguments: Vec<InputValueDefinition>,
    pub type_: Type,
    pub default_value: Option<ValueNode>,
    pub directives: Vec<Directive>,
}

/// `InputValueDefinitionNode`
#[derive(Debug, Clone)]
pub struct InputValueDefinition {
    pub pos: usize,
    pub description: Option<String>,
    pub name: Name,
    pub type_: Type,
    pub default_value: Option<ValueNode>,
    pub directives: Vec<Directive>,
}

/// `EnumValueDefinitionNode`
#[derive(Debug, Clone)]
pub struct EnumValueDefinition {
    pub pos: usize,
    pub description: Option<String>,
    pub name: Name,
    pub directives: Vec<Directive>,
}
