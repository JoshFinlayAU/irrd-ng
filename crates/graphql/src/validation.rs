//! graphql-core's `validate()`: the specified rules and ariadne's cost
//! validator, run as graphql-core runs them (a parallel visitor over the
//! document with a `TypeInfo`), so errors come out in the same order.

use std::collections::{HashMap, HashSet};

use crate::ast::*;
use crate::coerce::{Coercer, ScalarParsers, is_required, print_path_list};
use crate::error::{GraphQLError, print_type};
use crate::schema::{FieldRef, Kind, Schema, TypeId, TypeRef};
use crate::suggest::{did_you_mean_with, natural_cmp, suggestion_list};

const MAX_ERRORS: usize = 100;

/// The Python frames a validation rule's own recursion can use in v4
/// before `RecursionError`: `sys.getrecursionlimit()` (1000) less the
/// frames below the rule method.
///
/// Rules that follow fragment spreads (the cost validator,
/// `NoFragmentCycles`, `OverlappingFieldsCanBeMerged` and
/// `MaxIntrospectionDepth`) recurse once or twice per spread in
/// graphql-core and ariadne, so a long chain of fragments ends in a
/// `RecursionError` (P-54). irrd-ng counts the frames each of them would
/// use, and stops with the same error where Python would, instead of
/// recursing until its own stack runs out.
///
/// Measured with graphql-core 3.3.0 and ariadne 1.1.1 on Python 3.13:
/// with 7 frames below the rule method, 993 are left (a chain of 496
/// fragments ends the cost validator, 987 unused ones
/// `OverlappingFieldsCanBeMerged`). Under uvicorn, Starlette and
/// ariadne's handler v4 has about 24 more below it, which is also why
/// selection sets end at around 240 levels there and 246 bare: 969 left,
/// so a chain of 484 fragments spread from an operation is a
/// `RecursionError` in v4 and in irrd-ng.
pub(crate) const PY_STACK_FRAMES: usize = 969;

// ---- nodes ----

/// What a directive is attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Applied {
    Operation(OperationType),
    Field,
    FragmentSpread,
    InlineFragment,
    FragmentDefinition,
    VariableDefinition,
    Sdl(&'static str),
}

/// A node being visited.
#[derive(Clone, Copy)]
pub(crate) enum N<'a> {
    Document(&'a Document),
    Operation(&'a OperationDefinition),
    Fragment(&'a FragmentDefinition),
    VarDef(&'a VariableDefinition),
    Variable(&'a Variable),
    SelectionSet(&'a SelectionSet),
    Field(&'a Field),
    Spread(&'a FragmentSpread),
    Inline(&'a InlineFragment),
    Argument(&'a Argument),
    Directive(&'a Directive, Applied),
    NamedType(&'a NamedType),
    Value(&'a ValueNode),
    ObjectField(&'a ObjectField),
    TypeSystem(&'a TypeSystemDefinition),
}

impl N<'_> {
    fn addr(&self) -> usize {
        match self {
            N::Document(x) => *x as *const _ as usize,
            N::Operation(x) => *x as *const _ as usize,
            N::Fragment(x) => *x as *const _ as usize,
            N::VarDef(x) => *x as *const _ as usize,
            N::Variable(x) => *x as *const _ as usize,
            N::SelectionSet(x) => *x as *const _ as usize,
            N::Field(x) => *x as *const _ as usize,
            N::Spread(x) => *x as *const _ as usize,
            N::Inline(x) => *x as *const _ as usize,
            N::Argument(x) => *x as *const _ as usize,
            N::Directive(x, _) => *x as *const _ as usize,
            N::NamedType(x) => *x as *const _ as usize,
            N::Value(x) => *x as *const _ as usize,
            N::ObjectField(x) => *x as *const _ as usize,
            N::TypeSystem(x) => *x as *const _ as usize,
        }
    }
}

// ---- type info ----

#[derive(Debug, Default)]
pub(crate) struct TypeInfo {
    type_stack: Vec<Option<TypeRef>>,
    parent_type_stack: Vec<Option<TypeId>>,
    input_type_stack: Vec<Option<TypeRef>>,
    field_def_stack: Vec<Option<FieldRef>>,
    /// Whether the location has a default value.
    default_value_stack: Vec<bool>,
    directive: Option<usize>,
    argument: Option<(bool, usize)>,
}

impl TypeInfo {
    fn get_type(&self) -> Option<&TypeRef> {
        self.type_stack.last().and_then(Option::as_ref)
    }
    fn get_parent_type(&self) -> Option<TypeId> {
        self.parent_type_stack.last().copied().flatten()
    }
    fn get_input_type(&self) -> Option<&TypeRef> {
        self.input_type_stack.last().and_then(Option::as_ref)
    }
    fn get_parent_input_type(&self) -> Option<&TypeRef> {
        let n = self.input_type_stack.len();
        if n > 1 {
            self.input_type_stack[n - 2].as_ref()
        } else {
            None
        }
    }
    fn get_field_def(&self) -> Option<FieldRef> {
        self.field_def_stack.last().copied().flatten()
    }

    fn enter(&mut self, s: &Schema, n: &N<'_>) {
        match n {
            N::SelectionSet(_) => {
                let named = self.get_type().map(TypeRef::named);
                self.parent_type_stack
                    .push(named.filter(|t| s.t(*t).is_composite()));
            }
            N::Field(f) => {
                let fd = self
                    .get_parent_type()
                    .and_then(|p| s.get_field(p, &f.name.value));
                self.field_def_stack.push(fd);
                let ft = fd.map(|fd| s.field_def(fd).type_.clone());
                self.type_stack
                    .push(ft.filter(|t| s.t(t.named()).is_output()));
            }
            N::Directive(d, _) => {
                self.directive = s.directives.iter().position(|x| x.name == d.name.value);
            }
            N::Operation(o) => {
                let rt = s.root_type(o.operation);
                self.type_stack.push(
                    rt.filter(|t| s.t(*t).kind == Kind::Object)
                        .map(TypeRef::Named),
                );
            }
            N::Inline(i) => {
                let t = match &i.type_condition {
                    Some(tc) => s.type_id(&tc.name.value).map(TypeRef::Named),
                    None => self.get_type().map(|t| TypeRef::Named(t.named())),
                };
                self.type_stack
                    .push(t.filter(|t| s.t(t.named()).is_output()));
            }
            N::Fragment(f) => {
                let t = s.type_id(&f.type_condition.name.value).map(TypeRef::Named);
                self.type_stack
                    .push(t.filter(|t| s.t(t.named()).is_output()));
            }
            N::VarDef(v) => {
                let t = s.type_from_ast(&v.type_);
                self.input_type_stack
                    .push(t.filter(|t| s.t(t.named()).is_input()));
            }
            N::Argument(a) => {
                let (def, from_directive): (Option<&crate::schema::InputValue>, bool) =
                    if let Some(d) = self.directive {
                        (
                            s.directives[d].args.iter().find(|x| x.name == a.name.value),
                            true,
                        )
                    } else if let Some(fd) = self.get_field_def() {
                        (
                            s.field_def(fd).args.iter().find(|x| x.name == a.name.value),
                            false,
                        )
                    } else {
                        (None, false)
                    };
                let idx = def.and_then(|d| {
                    if from_directive {
                        self.directive.and_then(|di| {
                            s.directives[di].args.iter().position(|x| x.name == d.name)
                        })
                    } else {
                        self.get_field_def().and_then(|fd| {
                            s.field_def(fd).args.iter().position(|x| x.name == d.name)
                        })
                    }
                });
                self.argument = idx.map(|i| (from_directive, i));
                self.default_value_stack
                    .push(def.is_some_and(|d| d.default_value.is_some()));
                let t = def.map(|d| d.type_.clone());
                self.input_type_stack
                    .push(t.filter(|t| s.t(t.named()).is_input()));
            }
            N::Value(ValueNode::List(_, _)) => {
                let item = match self.get_input_type().map(TypeRef::nullable) {
                    Some(TypeRef::List(i)) => Some((**i).clone()),
                    _ => None,
                };
                self.default_value_stack.push(false);
                self.input_type_stack
                    .push(item.filter(|t| s.t(t.named()).is_input()));
            }
            N::ObjectField(of) => {
                let ot = self.get_input_type().map(TypeRef::named);
                let field = ot
                    .filter(|t| s.t(*t).kind == Kind::InputObject)
                    .and_then(|t| s.t(t).input_fields.iter().find(|f| f.name == of.name.value));
                self.default_value_stack
                    .push(field.is_some_and(|f| f.default_value.is_some()));
                self.input_type_stack.push(
                    field
                        .map(|f| f.type_.clone())
                        .filter(|t| s.t(t.named()).is_input()),
                );
            }
            _ => {}
        }
    }

    fn leave(&mut self, n: &N<'_>) {
        match n {
            N::SelectionSet(_) => {
                self.parent_type_stack.pop();
            }
            N::Field(_) => {
                self.field_def_stack.pop();
                self.type_stack.pop();
            }
            N::Directive(_, _) => self.directive = None,
            N::Operation(_) | N::Inline(_) | N::Fragment(_) => {
                self.type_stack.pop();
            }
            N::VarDef(_) => {
                self.input_type_stack.pop();
            }
            N::Argument(_) => {
                self.argument = None;
                self.default_value_stack.pop();
                self.input_type_stack.pop();
            }
            N::Value(ValueNode::List(_, _)) | N::ObjectField(_) => {
                self.default_value_stack.pop();
                self.input_type_stack.pop();
            }
            _ => {}
        }
    }
}

// ---- context ----

/// One variable usage.
#[derive(Debug, Clone)]
pub(crate) struct VariableUsage<'a> {
    node: &'a Variable,
    type_: Option<TypeRef>,
    has_default: bool,
}

pub(crate) struct Ctx<'a> {
    pub schema: &'a Schema,
    pub body: &'a [char],
    pub coercer: Coercer<'a>,
    pub ti: TypeInfo,
    pub errors: Vec<GraphQLError>,
    pub aborted: bool,
    /// Whether the current top-level definition is SDL.
    pub in_sdl: bool,
    /// A rule recursed past [`Ctx::py_frames`] (or through a fragment
    /// cycle in the cost validator), which ends in a `RecursionError` in
    /// v4. Validation stops at once, as the exception would stop it.
    pub recursion_error: bool,
    /// [`PY_STACK_FRAMES`], or another budget in tests.
    pub py_frames: usize,
    fragments: HashMap<&'a str, &'a FragmentDefinition>,
}

impl<'a> Ctx<'a> {
    /// `report_error()`, for rules in other modules.
    pub(crate) fn report_pub(&mut self, e: GraphQLError) {
        self.report(e);
    }

    /// `get_fragment()`, for rules in other modules.
    pub(crate) fn fragments_get(&self, name: &str) -> Option<&'a FragmentDefinition> {
        self.get_fragment(name)
    }

    /// The type info's parent type.
    pub(crate) fn ti_parent_type(&self) -> Option<TypeId> {
        self.ti.get_parent_type()
    }

    /// Validation has ended: too many errors, or a `RecursionError`.
    fn stopped(&self) -> bool {
        self.aborted || self.recursion_error
    }

    fn report(&mut self, e: GraphQLError) {
        if self.aborted {
            return;
        }
        if self.errors.len() >= MAX_ERRORS {
            self.aborted = true;
            return;
        }
        self.errors.push(e);
    }

    fn get_fragment(&self, name: &str) -> Option<&'a FragmentDefinition> {
        self.fragments.get(name).copied()
    }

    /// `get_fragment_spreads()`: depth-first with a stack, as Python.
    fn get_fragment_spreads(&self, set: &'a SelectionSet) -> Vec<&'a FragmentSpread> {
        let mut out = Vec::new();
        let mut stack = vec![set];
        while let Some(s) = stack.pop() {
            for sel in &s.selections {
                match sel {
                    Selection::FragmentSpread(fs) => out.push(fs),
                    Selection::Field(f) => {
                        if let Some(ss) = &f.selection_set {
                            stack.push(ss);
                        }
                    }
                    Selection::InlineFragment(i) => stack.push(&i.selection_set),
                }
            }
        }
        out
    }

    fn get_recursively_referenced_fragments(
        &self,
        op: &'a OperationDefinition,
    ) -> Vec<&'a FragmentDefinition> {
        let mut out = Vec::new();
        let mut names: HashSet<&str> = HashSet::new();
        let mut stack = vec![&op.selection_set];
        while let Some(s) = stack.pop() {
            for spread in self.get_fragment_spreads(s) {
                if names.insert(&spread.name.value)
                    && let Some(f) = self.get_fragment(&spread.name.value)
                {
                    out.push(f);
                    stack.push(&f.selection_set);
                }
            }
        }
        out
    }

    /// `get_recursive_variable_usages()`
    fn get_recursive_variable_usages(&self, op: &'a OperationDefinition) -> Vec<VariableUsage<'a>> {
        let mut out = Vec::new();
        let mut u = UsageWalker {
            s: self.schema,
            ti: TypeInfo::default(),
            out: &mut out,
        };
        u.operation(op);
        for f in self.get_recursively_referenced_fragments(op) {
            let mut u = UsageWalker {
                s: self.schema,
                ti: TypeInfo::default(),
                out: &mut out,
            };
            u.fragment(f);
        }
        out
    }

    fn get_variable_usages_fragment(&self, f: &'a FragmentDefinition) -> Vec<VariableUsage<'a>> {
        let mut out = Vec::new();
        let mut u = UsageWalker {
            s: self.schema,
            ti: TypeInfo::default(),
            out: &mut out,
        };
        u.fragment(f);
        out
    }
}

/// `VariableUsageVisitor` under a `TypeInfoVisitor`.
struct UsageWalker<'a, 'o> {
    s: &'a Schema,
    ti: TypeInfo,
    out: &'o mut Vec<VariableUsage<'a>>,
}

impl<'a> UsageWalker<'a, '_> {
    fn operation(&mut self, op: &'a OperationDefinition) {
        let n = N::Operation(op);
        self.ti.enter(self.s, &n);
        for d in &op.directives {
            self.directive(d, Applied::Operation(op.operation));
        }
        self.selection_set(&op.selection_set);
        self.ti.leave(&n);
    }

    fn fragment(&mut self, f: &'a FragmentDefinition) {
        let n = N::Fragment(f);
        self.ti.enter(self.s, &n);
        for d in &f.directives {
            self.directive(d, Applied::FragmentDefinition);
        }
        self.selection_set(&f.selection_set);
        self.ti.leave(&n);
    }

    fn selection_set(&mut self, ss: &'a SelectionSet) {
        let n = N::SelectionSet(ss);
        self.ti.enter(self.s, &n);
        for sel in &ss.selections {
            match sel {
                Selection::Field(f) => {
                    let n = N::Field(f);
                    self.ti.enter(self.s, &n);
                    for a in &f.arguments {
                        self.argument(a);
                    }
                    for d in &f.directives {
                        self.directive(d, Applied::Field);
                    }
                    if let Some(ss) = &f.selection_set {
                        self.selection_set(ss);
                    }
                    self.ti.leave(&n);
                }
                Selection::FragmentSpread(fs) => {
                    for d in &fs.directives {
                        self.directive(d, Applied::FragmentSpread);
                    }
                }
                Selection::InlineFragment(i) => {
                    let n = N::Inline(i);
                    self.ti.enter(self.s, &n);
                    for d in &i.directives {
                        self.directive(d, Applied::InlineFragment);
                    }
                    self.selection_set(&i.selection_set);
                    self.ti.leave(&n);
                }
            }
        }
        self.ti.leave(&n);
    }

    fn directive(&mut self, d: &'a Directive, applied: Applied) {
        let n = N::Directive(d, applied);
        self.ti.enter(self.s, &n);
        for a in &d.arguments {
            self.argument(a);
        }
        self.ti.leave(&n);
    }

    fn argument(&mut self, a: &'a Argument) {
        let n = N::Argument(a);
        self.ti.enter(self.s, &n);
        self.value(&a.value);
        self.ti.leave(&n);
    }

    fn value(&mut self, v: &'a ValueNode) {
        match v {
            ValueNode::Variable(var) => {
                self.out.push(VariableUsage {
                    node: var,
                    type_: self.ti.get_input_type().cloned(),
                    has_default: self.ti.default_value_stack.last().copied().unwrap_or(false),
                });
            }
            ValueNode::List(_, items) => {
                let n = N::Value(v);
                self.ti.enter(self.s, &n);
                for i in items {
                    self.value(i);
                }
                self.ti.leave(&n);
            }
            ValueNode::Object(_, fields) => {
                for f in fields {
                    let n = N::ObjectField(f);
                    self.ti.enter(self.s, &n);
                    self.value(&f.value);
                    self.ti.leave(&n);
                }
            }
            _ => {}
        }
    }
}

// ---- rules ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    Continue,
    Skip,
}

pub(crate) trait Rule<'a> {
    fn enter(&mut self, _cx: &mut Ctx<'a>, _n: &N<'a>) -> Flow {
        Flow::Continue
    }
    fn leave(&mut self, _cx: &mut Ctx<'a>, _n: &N<'a>) {}
}

struct Walker<'a, 'r> {
    cx: Ctx<'a>,
    rules: Vec<Box<dyn Rule<'a> + 'r>>,
    skipping: Vec<Option<usize>>,
}

impl<'a> Walker<'a, '_> {
    fn enter(&mut self, n: N<'a>) {
        self.cx.ti.enter(self.cx.schema, &n);
        for i in 0..self.rules.len() {
            if self.cx.stopped() {
                return;
            }
            if self.skipping[i].is_none() && self.rules[i].enter(&mut self.cx, &n) == Flow::Skip {
                self.skipping[i] = Some(n.addr());
            }
        }
    }

    fn leave(&mut self, n: N<'a>) {
        for i in 0..self.rules.len() {
            if self.cx.stopped() {
                return;
            }
            match self.skipping[i] {
                None => self.rules[i].leave(&mut self.cx, &n),
                Some(a) if a == n.addr() => self.skipping[i] = None,
                _ => {}
            }
        }
        self.cx.ti.leave(&n);
    }

    fn document(&mut self, d: &'a Document) {
        let n = N::Document(d);
        self.enter(n);
        for def in &d.definitions {
            match def {
                Definition::Operation(o) => {
                    self.cx.in_sdl = false;
                    self.operation(o);
                }
                Definition::Fragment(f) => {
                    self.cx.in_sdl = false;
                    self.fragment(f);
                }
                Definition::TypeSystem(t) => {
                    self.cx.in_sdl = true;
                    self.type_system(t);
                }
            }
            if self.cx.stopped() {
                return;
            }
        }
        self.leave(n);
    }

    fn operation(&mut self, o: &'a OperationDefinition) {
        let n = N::Operation(o);
        self.enter(n);
        for v in &o.variable_definitions {
            self.var_def(v);
        }
        for d in &o.directives {
            self.directive(d, Applied::Operation(o.operation));
        }
        self.selection_set(&o.selection_set);
        self.leave(n);
    }

    fn fragment(&mut self, f: &'a FragmentDefinition) {
        let n = N::Fragment(f);
        self.enter(n);
        self.named_type(&f.type_condition);
        for d in &f.directives {
            self.directive(d, Applied::FragmentDefinition);
        }
        self.selection_set(&f.selection_set);
        self.leave(n);
    }

    fn var_def(&mut self, v: &'a VariableDefinition) {
        let n = N::VarDef(v);
        self.enter(n);
        self.variable(&v.variable);
        self.type_(&v.type_);
        if let Some(dv) = &v.default_value {
            self.value(dv);
        }
        for d in &v.directives {
            self.directive(d, Applied::VariableDefinition);
        }
        self.leave(n);
    }

    fn variable(&mut self, v: &'a Variable) {
        let n = N::Variable(v);
        self.enter(n);
        self.leave(n);
    }

    fn type_(&mut self, t: &'a Type) {
        match t {
            Type::Named(nt) => self.named_type(nt),
            Type::List(_, i) | Type::NonNull(_, i) => self.type_(i),
        }
    }

    fn named_type(&mut self, nt: &'a NamedType) {
        let n = N::NamedType(nt);
        self.enter(n);
        self.leave(n);
    }

    fn selection_set(&mut self, ss: &'a SelectionSet) {
        let n = N::SelectionSet(ss);
        self.enter(n);
        for sel in &ss.selections {
            match sel {
                Selection::Field(f) => self.field(f),
                Selection::FragmentSpread(fs) => {
                    let n = N::Spread(fs);
                    self.enter(n);
                    for d in &fs.directives {
                        self.directive(d, Applied::FragmentSpread);
                    }
                    self.leave(n);
                }
                Selection::InlineFragment(i) => {
                    let n = N::Inline(i);
                    self.enter(n);
                    if let Some(tc) = &i.type_condition {
                        self.named_type(tc);
                    }
                    for d in &i.directives {
                        self.directive(d, Applied::InlineFragment);
                    }
                    self.selection_set(&i.selection_set);
                    self.leave(n);
                }
            }
        }
        self.leave(n);
    }

    fn field(&mut self, f: &'a Field) {
        let n = N::Field(f);
        self.enter(n);
        for a in &f.arguments {
            self.argument(a);
        }
        for d in &f.directives {
            self.directive(d, Applied::Field);
        }
        if let Some(ss) = &f.selection_set {
            self.selection_set(ss);
        }
        self.leave(n);
    }

    fn argument(&mut self, a: &'a Argument) {
        let n = N::Argument(a);
        self.enter(n);
        self.value(&a.value);
        self.leave(n);
    }

    fn directive(&mut self, d: &'a Directive, applied: Applied) {
        let n = N::Directive(d, applied);
        self.enter(n);
        for a in &d.arguments {
            self.argument(a);
        }
        self.leave(n);
    }

    fn value(&mut self, v: &'a ValueNode) {
        if let ValueNode::Variable(var) = v {
            self.variable(var);
            return;
        }
        let n = N::Value(v);
        self.enter(n);
        match v {
            ValueNode::List(_, items) => {
                for i in items {
                    self.value(i);
                }
            }
            ValueNode::Object(_, fields) => {
                for f in fields {
                    let n = N::ObjectField(f);
                    self.enter(n);
                    self.value(&f.value);
                    self.leave(n);
                }
            }
            _ => {}
        }
        self.leave(n);
    }

    fn type_system(&mut self, t: &'a TypeSystemDefinition) {
        // Only the parts rules look at: named types, directives and
        // default values.
        let n = N::TypeSystem(t);
        self.enter(n);
        let sdl = sdl_location(t.kind);
        for i in &t.interfaces {
            self.named_type(i);
        }
        for d in &t.directives {
            self.directive(d, Applied::Sdl(sdl));
        }
        for f in &t.fields {
            for a in &f.arguments {
                self.type_(&a.type_);
                if let Some(dv) = &a.default_value {
                    self.value(dv);
                }
                for d in &a.directives {
                    self.directive(d, Applied::Sdl("ARGUMENT_DEFINITION"));
                }
            }
            self.type_(&f.type_);
            if let Some(dv) = &f.default_value {
                self.value(dv);
            }
            let loc = if matches!(
                t.kind,
                TypeSystemKind::InputObjectTypeDefinition
                    | TypeSystemKind::InputObjectTypeExtension
            ) {
                "INPUT_FIELD_DEFINITION"
            } else {
                "FIELD_DEFINITION"
            };
            for d in &f.directives {
                self.directive(d, Applied::Sdl(loc));
            }
        }
        for ty in &t.types {
            self.named_type(ty);
        }
        for v in &t.values {
            for d in &v.directives {
                self.directive(d, Applied::Sdl("ENUM_VALUE"));
            }
        }
        for a in &t.arguments {
            self.type_(&a.type_);
            if let Some(dv) = &a.default_value {
                self.value(dv);
            }
            for d in &a.directives {
                self.directive(d, Applied::Sdl("ARGUMENT_DEFINITION"));
            }
        }
        for (_, nt) in &t.operation_types {
            self.named_type(nt);
        }
        self.leave(n);
    }
}

fn sdl_location(k: TypeSystemKind) -> &'static str {
    match k {
        TypeSystemKind::SchemaDefinition | TypeSystemKind::SchemaExtension => "SCHEMA",
        TypeSystemKind::ScalarTypeDefinition | TypeSystemKind::ScalarTypeExtension => "SCALAR",
        TypeSystemKind::ObjectTypeDefinition | TypeSystemKind::ObjectTypeExtension => "OBJECT",
        TypeSystemKind::InterfaceTypeDefinition | TypeSystemKind::InterfaceTypeExtension => {
            "INTERFACE"
        }
        TypeSystemKind::UnionTypeDefinition | TypeSystemKind::UnionTypeExtension => "UNION",
        TypeSystemKind::EnumTypeDefinition | TypeSystemKind::EnumTypeExtension => "ENUM",
        TypeSystemKind::InputObjectTypeDefinition | TypeSystemKind::InputObjectTypeExtension => {
            "INPUT_OBJECT"
        }
        TypeSystemKind::DirectiveDefinition | TypeSystemKind::DirectiveExtension => {
            "DIRECTIVE_DEFINITION"
        }
    }
}

/// Validate a document. `cost_limit` is ariadne's `cost_validator`
/// maximum (with `default_cost=1`), `None` to leave it out.
pub(crate) fn validate(
    schema: &Schema,
    scalars: &dyn ScalarParsers,
    doc: &Document,
    body: &[char],
    cost_limit: Option<i64>,
) -> Result<Vec<GraphQLError>, ()> {
    validate_with_frames(
        schema,
        scalars,
        doc,
        body,
        cost_limit,
        PY_STACK_FRAMES,
        None,
    )
}

/// [`validate`] for a request: the cost validator sees its `variables`
/// (DIV-008).
pub(crate) fn validate_request(
    schema: &Schema,
    scalars: &dyn ScalarParsers,
    doc: &Document,
    body: &[char],
    cost_limit: Option<i64>,
    variables: Option<crate::coerce::Variables>,
) -> Result<Vec<GraphQLError>, ()> {
    validate_with_frames(
        schema,
        scalars,
        doc,
        body,
        cost_limit,
        PY_STACK_FRAMES,
        variables,
    )
}

/// [`validate`] with `py_frames` Python frames for a rule's recursion
/// instead of [`PY_STACK_FRAMES`]. `Err` is the `RecursionError`.
pub(crate) fn validate_with_frames(
    schema: &Schema,
    scalars: &dyn ScalarParsers,
    doc: &Document,
    body: &[char],
    cost_limit: Option<i64>,
    py_frames: usize,
    variables: Option<crate::coerce::Variables>,
) -> Result<Vec<GraphQLError>, ()> {
    // A dict comprehension: the last fragment of a name wins.
    let mut fragments: HashMap<&str, &FragmentDefinition> = HashMap::new();
    for d in &doc.definitions {
        if let Definition::Fragment(f) = d {
            fragments.insert(f.name.value.as_str(), f);
        }
    }
    let cx = Ctx {
        schema,
        body,
        coercer: Coercer { schema, scalars },
        ti: TypeInfo::default(),
        errors: Vec::new(),
        aborted: false,
        in_sdl: false,
        recursion_error: false,
        py_frames,
        fragments,
    };
    let mut rules: Vec<Box<dyn Rule<'_>>> = vec![
        Box::new(ExecutableDefinitions),
        Box::new(KnownOperationTypes),
        Box::new(UniqueOperationNames::default()),
        Box::new(LoneAnonymousOperation::default()),
        Box::new(KnownTypeNames::new(schema, doc)),
        Box::new(FragmentsOnCompositeTypes),
        Box::new(VariablesAreInputTypes),
        Box::new(ScalarLeafs),
        Box::new(FieldsOnCorrectType),
        Box::new(UniqueFragmentNames::default()),
        Box::new(KnownFragmentNames),
        Box::new(NoUnusedFragments::default()),
        Box::new(PossibleFragmentSpreads),
        Box::new(NoFragmentCycles::default()),
        Box::new(UniqueVariableNames),
        Box::new(NoUndefinedVariables::default()),
        Box::new(NoUnusedVariables),
        Box::new(KnownDirectives::new(schema, doc)),
        Box::new(UniqueDirectivesPerLocation::new(schema, doc)),
        Box::new(DeferStreamOnValidOperations),
        Box::new(DeferStreamLabel::default()),
        Box::new(StreamOnListField),
        Box::new(KnownArgumentNames::new(schema, doc)),
        Box::new(UniqueArgumentNames),
        Box::new(ValuesOfCorrectType),
        Box::new(ProvidedRequiredArguments::new(schema, doc)),
        Box::new(VariablesInAllowedPosition::default()),
        Box::new(crate::overlap::OverlappingFields::default()),
        Box::new(UniqueInputFieldNames::default()),
        Box::new(MaxIntrospectionDepth),
    ];
    if let Some(limit) = cost_limit {
        rules.push(Box::new(crate::cost::CostValidator::new(limit, variables)));
    }
    let n = rules.len();
    let mut w = Walker {
        cx,
        rules,
        skipping: vec![None; n],
    };
    w.document(doc);
    if w.cx.recursion_error {
        return Err(());
    }
    let mut errors = std::mem::take(&mut w.cx.errors);
    if w.cx.aborted {
        errors.push(GraphQLError::plain(
            "Too many validation errors, error limit reached. Validation aborted.",
        ));
    }
    Ok(errors)
}

// ---- individual rules ----

struct ExecutableDefinitions;
impl<'a> Rule<'a> for ExecutableDefinitions {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        if let N::Document(d) = n {
            for def in &d.definitions {
                if let Definition::TypeSystem(t) = def {
                    let name = if matches!(
                        t.kind,
                        TypeSystemKind::SchemaDefinition | TypeSystemKind::SchemaExtension
                    ) {
                        "schema".to_owned()
                    } else {
                        format!("'{}'", t.name.as_ref().map_or("", |n| n.value.as_str()))
                    };
                    cx.report(GraphQLError::new(
                        format!("The {name} definition is not executable."),
                        vec![t.pos],
                    ));
                }
            }
            return Flow::Skip;
        }
        Flow::Continue
    }
}

struct KnownOperationTypes;
impl<'a> Rule<'a> for KnownOperationTypes {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        if let N::Operation(o) = n
            && cx.schema.root_type(o.operation).is_none()
        {
            cx.report(GraphQLError::new(
                format!(
                    "The {} operation is not supported by the schema.",
                    o.operation.as_str()
                ),
                vec![o.pos],
            ));
        }
        Flow::Continue
    }
}

#[derive(Default)]
struct UniqueOperationNames {
    known: HashMap<String, usize>,
}
impl<'a> Rule<'a> for UniqueOperationNames {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        match n {
            N::Operation(o) => {
                if let Some(name) = &o.name {
                    if let Some(&prev) = self.known.get(&name.value) {
                        cx.report(GraphQLError::new(
                            format!("There can be only one operation named '{}'.", name.value),
                            vec![prev, name.pos],
                        ));
                    } else {
                        self.known.insert(name.value.clone(), name.pos);
                    }
                }
                Flow::Skip
            }
            N::Fragment(_) => Flow::Skip,
            _ => Flow::Continue,
        }
    }
}

#[derive(Default)]
struct LoneAnonymousOperation {
    count: usize,
}
impl<'a> Rule<'a> for LoneAnonymousOperation {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        match n {
            N::Document(d) => {
                self.count = d
                    .definitions
                    .iter()
                    .filter(|x| matches!(x, Definition::Operation(_)))
                    .count();
            }
            N::Operation(o) if o.name.is_none() && self.count > 1 => {
                cx.report(GraphQLError::new(
                    "This anonymous operation must be the only defined operation.",
                    vec![o.pos],
                ));
            }
            _ => {}
        }
        Flow::Continue
    }
}

struct KnownTypeNames {
    existing: Vec<String>,
    defined: HashSet<String>,
    type_names: Vec<String>,
}
impl KnownTypeNames {
    fn new(schema: &Schema, doc: &Document) -> Self {
        let existing: Vec<String> = schema.types.iter().map(|t| t.name.clone()).collect();
        let defined: Vec<String> = doc
            .definitions
            .iter()
            .filter_map(|d| match d {
                Definition::TypeSystem(t) if t.kind.is_type_definition() => {
                    t.name.as_ref().map(|n| n.value.clone())
                }
                _ => None,
            })
            .collect();
        let mut type_names = existing.clone();
        type_names.extend(defined.iter().cloned());
        KnownTypeNames {
            existing,
            defined: defined.into_iter().collect(),
            type_names,
        }
    }
}
impl<'a> Rule<'a> for KnownTypeNames {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        let N::NamedType(nt) = n else {
            return Flow::Continue;
        };
        let name = &nt.name.value;
        if self.existing.contains(name) || self.defined.contains(name) {
            return Flow::Continue;
        }
        // `ancestors[2]` is the top-level definition.
        let is_sdl = cx.in_sdl;
        let standard: Vec<&str> = crate::schema::SPECIFIED_SCALARS
            .iter()
            .chain(crate::schema::INTROSPECTION_TYPES.iter())
            .copied()
            .collect();
        if is_sdl && standard.contains(&name.as_str()) {
            return Flow::Continue;
        }
        let mut options: Vec<&str> = Vec::new();
        if is_sdl {
            // `list(standard_type_names)`: a set, in CPython's order for
            // these strings, which varies; sorted here.
            let mut st = standard.clone();
            st.sort_unstable();
            options.extend(st);
        }
        options.extend(self.type_names.iter().map(String::as_str));
        let sugg = suggestion_list(name, &options);
        cx.report(GraphQLError::new(
            format!("Unknown type '{name}'.{}", did_you_mean_with(&sugg, None)),
            vec![nt.pos],
        ));
        Flow::Continue
    }
}

struct FragmentsOnCompositeTypes;
impl<'a> Rule<'a> for FragmentsOnCompositeTypes {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        match n {
            N::Inline(i) => {
                if let Some(tc) = &i.type_condition
                    && let Some(t) = cx.schema.type_id(&tc.name.value)
                    && !cx.schema.t(t).is_composite()
                {
                    cx.report(GraphQLError::new(
                        format!(
                            "Fragment cannot condition on non composite type '{}'.",
                            tc.name.value
                        ),
                        vec![tc.pos],
                    ));
                }
            }
            N::Fragment(f) => {
                let tc = &f.type_condition;
                if let Some(t) = cx.schema.type_id(&tc.name.value)
                    && !cx.schema.t(t).is_composite()
                {
                    cx.report(GraphQLError::new(
                        format!(
                            "Fragment '{}' cannot condition on non composite type '{}'.",
                            f.name.value, tc.name.value
                        ),
                        vec![tc.pos],
                    ));
                }
            }
            _ => {}
        }
        Flow::Continue
    }
}

struct VariablesAreInputTypes;
impl<'a> Rule<'a> for VariablesAreInputTypes {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        if let N::VarDef(v) = n
            && let Some(t) = cx.schema.type_from_ast(&v.type_)
            && !cx.schema.t(t.named()).is_input()
        {
            cx.report(GraphQLError::new(
                format!(
                    "Variable '${}' cannot be non-input type '{}'.",
                    v.variable.name.value,
                    print_type(&v.type_)
                ),
                vec![v.type_.pos()],
            ));
        }
        Flow::Continue
    }
}

struct ScalarLeafs;
impl<'a> Rule<'a> for ScalarLeafs {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        let N::Field(f) = n else {
            return Flow::Continue;
        };
        let Some(t) = cx.ti.get_type().cloned() else {
            return Flow::Continue;
        };
        let ts = cx.schema.type_str(&t);
        let name = &f.name.value;
        if cx.schema.t(t.named()).is_leaf() {
            if let Some(ss) = &f.selection_set {
                cx.report(GraphQLError::new(
                    format!(
                        "Field '{name}' must not have a selection since type '{ts}' has no subfields."
                    ),
                    vec![ss.pos],
                ));
            }
        } else if f.selection_set.is_none() {
            cx.report(GraphQLError::new(
                format!(
                    "Field '{name}' of type '{ts}' must have a selection of subfields. Did you mean '{name} {{ ... }}'?"
                ),
                vec![f.pos],
            ));
        }
        Flow::Continue
    }
}

struct FieldsOnCorrectType;
impl<'a> Rule<'a> for FieldsOnCorrectType {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        let N::Field(f) = n else {
            return Flow::Continue;
        };
        let Some(parent) = cx.ti.get_parent_type() else {
            return Flow::Continue;
        };
        if cx.ti.get_field_def().is_some() {
            return Flow::Continue;
        }
        let s = cx.schema;
        let name = &f.name.value;
        let types = suggested_type_names(s, parent, name);
        let mut suggestion = did_you_mean_with(&types, Some("to use an inline fragment on"));
        if suggestion.is_empty() {
            let pt = s.t(parent);
            let fields: Vec<&str> = if matches!(pt.kind, Kind::Object | Kind::Interface) {
                pt.fields.iter().map(|f| f.name.as_str()).collect()
            } else {
                Vec::new()
            };
            suggestion = did_you_mean_with(&suggestion_list(name, &fields), None);
        }
        cx.report(GraphQLError::new(
            format!(
                "Cannot query field '{name}' on type '{}'.{suggestion}",
                s.t(parent).name
            ),
            vec![f.pos],
        ));
        Flow::Continue
    }
}

fn suggested_type_names(s: &Schema, parent: TypeId, field: &str) -> Vec<String> {
    if !s.t(parent).is_abstract() {
        return Vec::new();
    }
    let mut suggested: Vec<TypeId> = Vec::new();
    let mut usage: HashMap<TypeId, usize> = HashMap::new();
    for &pt in s.possible_types(parent) {
        if s.t(pt).field(field).is_none() {
            continue;
        }
        if !suggested.contains(&pt) {
            suggested.push(pt);
        }
        usage.insert(pt, 1);
        for &iface in &s.t(pt).interfaces {
            if s.t(iface).field(field).is_none() {
                continue;
            }
            if !suggested.contains(&iface) {
                suggested.push(iface);
            }
            *usage.entry(iface).or_insert(0) += 1;
        }
    }
    suggested.sort_by(|a, b| {
        let ua = usage.get(a).copied().unwrap_or(0);
        let ub = usage.get(b).copied().unwrap_or(0);
        if ua != ub {
            return ub.cmp(&ua);
        }
        if s.t(*a).kind == Kind::Interface && s.is_sub_type(*a, *b) {
            return std::cmp::Ordering::Less;
        }
        if s.t(*b).kind == Kind::Interface && s.is_sub_type(*b, *a) {
            return std::cmp::Ordering::Greater;
        }
        natural_cmp(&s.t(*a).name, &s.t(*b).name)
    });
    suggested.into_iter().map(|t| s.t(t).name.clone()).collect()
}

#[derive(Default)]
struct UniqueFragmentNames {
    known: HashMap<String, usize>,
}
impl<'a> Rule<'a> for UniqueFragmentNames {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        match n {
            N::Operation(_) => Flow::Skip,
            N::Fragment(f) => {
                let name = &f.name.value;
                if let Some(&prev) = self.known.get(name) {
                    cx.report(GraphQLError::new(
                        format!("There can be only one fragment named '{name}'."),
                        vec![prev, f.name.pos],
                    ));
                } else {
                    self.known.insert(name.clone(), f.name.pos);
                }
                Flow::Skip
            }
            _ => Flow::Continue,
        }
    }
}

struct KnownFragmentNames;
impl<'a> Rule<'a> for KnownFragmentNames {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        if let N::Spread(s) = n
            && cx.get_fragment(&s.name.value).is_none()
        {
            cx.report(GraphQLError::new(
                format!("Unknown fragment '{}'.", s.name.value),
                vec![s.name.pos],
            ));
        }
        Flow::Continue
    }
}

#[derive(Default)]
struct NoUnusedFragments<'a> {
    ops: Vec<&'a OperationDefinition>,
    frags: Vec<&'a FragmentDefinition>,
}
impl<'a> Rule<'a> for NoUnusedFragments<'a> {
    fn enter(&mut self, _cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        match n {
            N::Operation(o) => {
                self.ops.push(o);
                Flow::Skip
            }
            N::Fragment(f) => {
                self.frags.push(f);
                Flow::Skip
            }
            _ => Flow::Continue,
        }
    }
    fn leave(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) {
        if let N::Document(_) = n {
            let mut used: HashSet<&str> = HashSet::new();
            for op in &self.ops {
                for f in cx.get_recursively_referenced_fragments(op) {
                    used.insert(&f.name.value);
                }
            }
            for f in &self.frags {
                if !used.contains(f.name.value.as_str()) {
                    cx.report(GraphQLError::new(
                        format!("Fragment '{}' is never used.", f.name.value),
                        vec![f.pos],
                    ));
                }
            }
        }
    }
}

struct PossibleFragmentSpreads;
impl<'a> Rule<'a> for PossibleFragmentSpreads {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        let s = cx.schema;
        match n {
            N::Inline(i) => {
                let frag = cx.ti.get_type().map(TypeRef::named);
                let parent = cx.ti.get_parent_type();
                if let (Some(f), Some(p)) = (frag, parent)
                    && s.t(f).is_composite()
                    && s.t(p).is_composite()
                    && !s.do_types_overlap(f, p)
                {
                    cx.report(GraphQLError::new(
                        format!(
                            "Fragment cannot be spread here as objects of type '{}' can never be of type '{}'.",
                            s.t(p).name,
                            s.t(f).name
                        ),
                        vec![i.pos],
                    ));
                }
            }
            N::Spread(sp) => {
                let frag = cx
                    .get_fragment(&sp.name.value)
                    .and_then(|f| s.type_id(&f.type_condition.name.value))
                    .filter(|t| s.t(*t).is_composite());
                let parent = cx.ti.get_parent_type();
                if let (Some(f), Some(p)) = (frag, parent)
                    && !s.do_types_overlap(f, p)
                {
                    cx.report(GraphQLError::new(
                        format!(
                            "Fragment '{}' cannot be spread here as objects of type '{}' can never be of type '{}'.",
                            sp.name.value,
                            s.t(p).name,
                            s.t(f).name
                        ),
                        vec![sp.pos],
                    ));
                }
            }
            _ => {}
        }
        Flow::Continue
    }
}

#[derive(Default)]
struct NoFragmentCycles<'a> {
    visited: HashSet<String>,
    spread_path: Vec<&'a FragmentSpread>,
    index: HashMap<String, usize>,
}
/// One `detect_cycle_recursive()` call on [`NoFragmentCycles`]'s explicit
/// stack: the fragment and the spreads it has yet to follow.
struct CycleFrame<'a> {
    name: &'a str,
    spreads: Vec<&'a FragmentSpread>,
    next: usize,
}

impl<'a> NoFragmentCycles<'a> {
    /// `detect_cycle_recursive()` from `f`, depth first as graphql-core
    /// recurses, but on an explicit stack. graphql-core uses a frame per
    /// fragment on the path plus one for `get_fragment_spreads()`; past
    /// [`Ctx::py_frames`] that is its `RecursionError`.
    fn detect(&mut self, cx: &mut Ctx<'a>, f: &'a FragmentDefinition) {
        let mut stack: Vec<CycleFrame<'a>> = Vec::new();
        if let Some(frame) = self.enter_fragment(cx, f, 0) {
            stack.push(frame);
        }
        while let Some(top) = stack.last_mut() {
            if cx.recursion_error {
                return;
            }
            let Some(&sp) = top.spreads.get(top.next) else {
                // The call returns: its fragment leaves the path, and the
                // spread that led to it is popped in the caller.
                self.index.remove(top.name);
                stack.pop();
                if !stack.is_empty() {
                    self.spread_path.pop();
                }
                continue;
            };
            top.next += 1;
            let sname = sp.name.value.as_str();
            let cycle = self.index.get(sname).copied();
            self.spread_path.push(sp);
            match cycle {
                None => {
                    let depth = stack.len();
                    match cx.get_fragment(sname) {
                        Some(sf) => match self.enter_fragment(cx, sf, depth) {
                            // Popped from spread_path when the call returns.
                            Some(frame) => stack.push(frame),
                            None => {
                                self.spread_path.pop();
                            }
                        },
                        None => {
                            self.spread_path.pop();
                        }
                    }
                }
                Some(ci) => {
                    let path = &self.spread_path[ci..];
                    let via: Vec<String> = path[..path.len() - 1]
                        .iter()
                        .map(|s| format!("'{}'", s.name.value))
                        .collect();
                    let msg = if via.is_empty() {
                        format!("Cannot spread fragment '{sname}' within itself.")
                    } else {
                        format!(
                            "Cannot spread fragment '{sname}' within itself via {}.",
                            via.join(", ")
                        )
                    };
                    let positions = path.iter().map(|s| s.pos).collect();
                    cx.report(GraphQLError::new(msg, positions));
                    self.spread_path.pop();
                }
            }
        }
    }

    /// The start of a `detect_cycle_recursive()` call made with `depth`
    /// calls below it: `None` when it returns at once (already visited,
    /// no spreads, or a `RecursionError`).
    fn enter_fragment(
        &mut self,
        cx: &mut Ctx<'a>,
        f: &'a FragmentDefinition,
        depth: usize,
    ) -> Option<CycleFrame<'a>> {
        if depth + 1 > cx.py_frames {
            cx.recursion_error = true;
            return None;
        }
        let name = f.name.value.as_str();
        if !self.visited.insert(name.to_owned()) {
            return None;
        }
        // get_fragment_spreads() is one frame more.
        if depth + 2 > cx.py_frames {
            cx.recursion_error = true;
            return None;
        }
        let spreads = cx.get_fragment_spreads(&f.selection_set);
        if spreads.is_empty() {
            return None;
        }
        self.index.insert(name.to_owned(), self.spread_path.len());
        Some(CycleFrame {
            name,
            spreads,
            next: 0,
        })
    }
}
impl<'a> Rule<'a> for NoFragmentCycles<'a> {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        match n {
            N::Operation(_) => Flow::Skip,
            N::Fragment(f) => {
                self.detect(cx, f);
                Flow::Skip
            }
            _ => Flow::Continue,
        }
    }
}

struct UniqueVariableNames;
impl<'a> Rule<'a> for UniqueVariableNames {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        if let N::Operation(o) = n {
            let mut groups: Vec<(&str, Vec<usize>)> = Vec::new();
            for v in &o.variable_definitions {
                let name = v.variable.name.value.as_str();
                match groups.iter_mut().find(|(k, _)| *k == name) {
                    Some(g) => g.1.push(v.variable.name.pos),
                    None => groups.push((name, vec![v.variable.name.pos])),
                }
            }
            for (name, nodes) in groups {
                if nodes.len() > 1 {
                    cx.report(GraphQLError::new(
                        format!("There can be only one variable named '${name}'."),
                        nodes,
                    ));
                }
            }
        }
        Flow::Continue
    }
}

#[derive(Default)]
struct NoUndefinedVariables {
    defined: HashSet<String>,
}
impl<'a> Rule<'a> for NoUndefinedVariables {
    fn enter(&mut self, _cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        match n {
            N::Operation(_) => self.defined.clear(),
            N::VarDef(v) => {
                self.defined.insert(v.variable.name.value.clone());
            }
            _ => {}
        }
        Flow::Continue
    }
    fn leave(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) {
        if let N::Operation(o) = n {
            for u in cx.get_recursive_variable_usages(o) {
                let name = &u.node.name.value;
                if !self.defined.contains(name) {
                    let msg = match &o.name {
                        Some(on) => format!(
                            "Variable '${name}' is not defined by operation '{}'.",
                            on.value
                        ),
                        None => format!("Variable '${name}' is not defined."),
                    };
                    cx.report(GraphQLError::new(msg, vec![u.node.pos, o.pos]));
                }
            }
        }
    }
}

struct NoUnusedVariables;
impl<'a> Rule<'a> for NoUnusedVariables {
    fn leave(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) {
        if let N::Operation(o) = n {
            let used: HashSet<String> = cx
                .get_recursive_variable_usages(o)
                .iter()
                .map(|u| u.node.name.value.clone())
                .collect();
            for v in &o.variable_definitions {
                let name = &v.variable.name.value;
                if !used.contains(name) {
                    let msg = match &o.name {
                        Some(on) => format!(
                            "Variable '${name}' is never used in operation '{}'.",
                            on.value
                        ),
                        None => format!("Variable '${name}' is never used."),
                    };
                    cx.report(GraphQLError::new(msg, vec![v.pos]));
                }
            }
        }
        if let N::Fragment(f) = n {
            // Fragment variables are experimental and off; nothing to do.
            let _ = cx.get_variable_usages_fragment(f);
        }
    }
}

struct KnownDirectives {
    locations: HashMap<String, Vec<String>>,
}
impl KnownDirectives {
    fn new(s: &Schema, doc: &Document) -> Self {
        let mut locations: HashMap<String, Vec<String>> = s
            .directives
            .iter()
            .map(|d| (d.name.clone(), d.locations.clone()))
            .collect();
        for d in &doc.definitions {
            if let Definition::TypeSystem(t) = d
                && t.kind == TypeSystemKind::DirectiveDefinition
            {
                locations.insert(
                    t.name.as_ref().map(|n| n.value.clone()).unwrap_or_default(),
                    t.locations.iter().map(|l| l.value.clone()).collect(),
                );
            }
        }
        KnownDirectives { locations }
    }
}
impl<'a> Rule<'a> for KnownDirectives {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        let N::Directive(d, applied) = n else {
            return Flow::Continue;
        };
        let name = &d.name.value;
        match self.locations.get(name) {
            Some(locs) if !locs.is_empty() => {
                let loc = match applied {
                    Applied::Operation(OperationType::Query) => "QUERY",
                    Applied::Operation(OperationType::Mutation) => "MUTATION",
                    Applied::Operation(OperationType::Subscription) => "SUBSCRIPTION",
                    Applied::Field => "FIELD",
                    Applied::FragmentSpread => "FRAGMENT_SPREAD",
                    Applied::InlineFragment => "INLINE_FRAGMENT",
                    Applied::FragmentDefinition => "FRAGMENT_DEFINITION",
                    Applied::VariableDefinition => "VARIABLE_DEFINITION",
                    Applied::Sdl(l) => l,
                };
                if !locs.iter().any(|l| l == loc) {
                    // DirectiveLocation.value: lower case words.
                    let shown = loc.to_lowercase().replace('_', " ");
                    cx.report(GraphQLError::new(
                        format!("Directive '@{name}' may not be used on {shown}."),
                        vec![d.pos],
                    ));
                }
            }
            _ => cx.report(GraphQLError::new(
                format!("Unknown directive '@{name}'."),
                vec![d.pos],
            )),
        }
        Flow::Continue
    }
}

struct UniqueDirectivesPerLocation {
    unique: HashMap<String, bool>,
    type_directives: HashMap<String, HashMap<String, usize>>,
    schema_directives: HashMap<String, usize>,
}
impl UniqueDirectivesPerLocation {
    fn new(s: &Schema, doc: &Document) -> Self {
        let mut unique: HashMap<String, bool> = s
            .directives
            .iter()
            .map(|d| (d.name.clone(), !d.repeatable))
            .collect();
        for d in &doc.definitions {
            if let Definition::TypeSystem(t) = d
                && t.kind == TypeSystemKind::DirectiveDefinition
            {
                unique.insert(
                    t.name.as_ref().map(|n| n.value.clone()).unwrap_or_default(),
                    !t.repeatable,
                );
            }
        }
        UniqueDirectivesPerLocation {
            unique,
            type_directives: HashMap::new(),
            schema_directives: HashMap::new(),
        }
    }

    fn check(&mut self, cx: &mut Ctx<'_>, dirs: &[Directive], seen: &mut HashMap<String, usize>) {
        for d in dirs {
            let name = &d.name.value;
            if self.unique.get(name).copied().unwrap_or(false) {
                if let Some(&prev) = seen.get(name) {
                    cx.report(GraphQLError::new(
                        format!("The directive '@{name}' can only be used once at this location."),
                        vec![prev, d.pos],
                    ));
                } else {
                    seen.insert(name.clone(), d.pos);
                }
            }
        }
    }
}
impl<'a> Rule<'a> for UniqueDirectivesPerLocation {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        let dirs: &[Directive] = match n {
            N::Operation(o) => &o.directives,
            N::Fragment(f) => &f.directives,
            N::VarDef(v) => &v.directives,
            N::Field(f) => &f.directives,
            N::Spread(s) => &s.directives,
            N::Inline(i) => &i.directives,
            N::TypeSystem(t) => {
                if t.directives.is_empty() {
                    return Flow::Continue;
                }
                let mut seen = if matches!(
                    t.kind,
                    TypeSystemKind::SchemaDefinition | TypeSystemKind::SchemaExtension
                ) {
                    std::mem::take(&mut self.schema_directives)
                } else {
                    let key = t.name.as_ref().map(|n| n.value.clone()).unwrap_or_default();
                    self.type_directives.remove(&key).unwrap_or_default()
                };
                self.check(cx, &t.directives, &mut seen);
                if matches!(
                    t.kind,
                    TypeSystemKind::SchemaDefinition | TypeSystemKind::SchemaExtension
                ) {
                    self.schema_directives = seen;
                } else {
                    let key = t.name.as_ref().map(|n| n.value.clone()).unwrap_or_default();
                    self.type_directives.insert(key, seen);
                }
                return Flow::Continue;
            }
            _ => return Flow::Continue,
        };
        if dirs.is_empty() {
            return Flow::Continue;
        }
        let mut seen = HashMap::new();
        self.check(cx, dirs, &mut seen);
        Flow::Continue
    }
}

/// `DeferStreamDirectiveOnValidOperationsRule`: only subscriptions.
struct DeferStreamOnValidOperations;
impl DeferStreamOnValidOperations {
    fn if_arg(d: &Directive) -> Option<&ValueNode> {
        d.arguments
            .iter()
            .find(|a| a.name.value == "if")
            .map(|a| &a.value)
    }

    /// `forbid_unconditional_defer_stream()`, the `frames`-th Python frame
    /// of its recursion (one per selection set, and one more for the
    /// `get_directive()` it calls on each selection).
    fn forbid<'a>(
        cx: &mut Ctx<'a>,
        set: &'a SelectionSet,
        parents: &[usize],
        visited: &mut HashSet<String>,
        frames: usize,
    ) {
        if frames + 1 > cx.py_frames {
            cx.recursion_error = true;
        }
        for sel in &set.selections {
            if cx.recursion_error {
                return;
            }
            let dirs = sel.directives();
            if let Some(skip) = dirs.iter().find(|d| d.name.value == "skip") {
                let can = match Self::if_arg(skip) {
                    None => true,
                    Some(ValueNode::Boolean(_, b)) => *b,
                    Some(_) => true,
                };
                if can {
                    continue;
                }
            }
            if let Some(inc) = dirs.iter().find(|d| d.name.value == "include") {
                let can = match Self::if_arg(inc) {
                    None => false,
                    Some(ValueNode::Boolean(_, b)) => !*b,
                    Some(_) => true,
                };
                if can {
                    continue;
                }
            }
            for d in dirs {
                let msg = match d.name.value.as_str() {
                    "defer" => {
                        "Defer directive not supported on subscription operations. Disable `@defer` by setting the `if` argument to `false`."
                    }
                    "stream" => {
                        "Stream directive not supported on subscription operations. Disable `@stream` by setting the `if` argument to `false`."
                    }
                    _ => continue,
                };
                let can_be_false = match Self::if_arg(d) {
                    None => false,
                    Some(ValueNode::Boolean(_, b)) => !*b,
                    Some(ValueNode::Variable(_)) => true,
                    Some(_) => false,
                };
                if can_be_false {
                    continue;
                }
                let mut pos = vec![d.pos];
                pos.extend_from_slice(parents);
                cx.report(GraphQLError::new(msg, pos));
            }
            match sel {
                Selection::FragmentSpread(fs) => {
                    if !visited.insert(fs.name.value.clone()) {
                        continue;
                    }
                    if let Some(f) = cx.get_fragment(&fs.name.value) {
                        let mut p = vec![fs.pos];
                        p.extend_from_slice(parents);
                        Self::forbid(cx, &f.selection_set, &p, visited, frames + 1);
                    }
                }
                Selection::Field(f) => {
                    if let Some(ss) = &f.selection_set {
                        Self::forbid(cx, ss, parents, visited, frames + 1);
                    }
                }
                Selection::InlineFragment(i) => {
                    Self::forbid(cx, &i.selection_set, parents, visited, frames + 1)
                }
            }
        }
    }
}
impl<'a> Rule<'a> for DeferStreamOnValidOperations {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        if let N::Operation(o) = n
            && o.operation == OperationType::Subscription
        {
            let mut visited = HashSet::new();
            Self::forbid(cx, &o.selection_set, &[], &mut visited, 1);
        }
        Flow::Continue
    }
}

#[derive(Default)]
struct DeferStreamLabel {
    known: HashMap<String, usize>,
}
impl<'a> Rule<'a> for DeferStreamLabel {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        let N::Directive(d, _) = n else {
            return Flow::Continue;
        };
        if d.name.value != "defer" && d.name.value != "stream" {
            return Flow::Continue;
        }
        let Some(label) = d.arguments.iter().find(|a| a.name.value == "label") else {
            return Flow::Continue;
        };
        match &label.value {
            ValueNode::Null(_) => {}
            ValueNode::String(_, s, _) => {
                if let Some(&prev) = self.known.get(s) {
                    cx.report(GraphQLError::new(
                        "Defer/Stream directive label argument must be unique.",
                        vec![prev, d.pos],
                    ));
                } else {
                    self.known.insert(s.clone(), d.pos);
                }
            }
            _ => {
                let mut name = d.name.value.clone();
                if let Some(first) = name.get_mut(0..1) {
                    first.make_ascii_uppercase();
                }
                cx.report(GraphQLError::new(
                    format!("{name} directive label argument must be a static string."),
                    vec![d.pos],
                ));
            }
        }
        Flow::Continue
    }
}

struct StreamOnListField;
impl<'a> Rule<'a> for StreamOnListField {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        let N::Directive(d, _) = n else {
            return Flow::Continue;
        };
        if d.name.value != "stream" {
            return Flow::Continue;
        }
        let (Some(fd), Some(parent)) = (cx.ti.get_field_def(), cx.ti.get_parent_type()) else {
            return Flow::Continue;
        };
        let def = cx.schema.field_def(fd);
        let is_list =
            def.type_.is_list() || matches!(&def.type_, TypeRef::NonNull(i) if i.is_list());
        if !is_list {
            let field_name = match fd {
                FieldRef::Field(t, i) if t == parent => {
                    format!(" '{}'", cx.schema.t(t).fields[i].name)
                }
                _ => String::new(),
            };
            cx.report(GraphQLError::new(
                format!(
                    "Stream directive cannot be used on non-list field{field_name} on type '{}'.",
                    cx.schema.t(parent).name
                ),
                vec![d.pos],
            ));
        }
        Flow::Continue
    }
}

struct KnownArgumentNames {
    directive_args: HashMap<String, Vec<String>>,
}
impl KnownArgumentNames {
    fn new(s: &Schema, doc: &Document) -> Self {
        let mut directive_args: HashMap<String, Vec<String>> = s
            .directives
            .iter()
            .map(|d| {
                (
                    d.name.clone(),
                    d.args.iter().map(|a| a.name.clone()).collect(),
                )
            })
            .collect();
        for d in &doc.definitions {
            if let Definition::TypeSystem(t) = d
                && t.kind == TypeSystemKind::DirectiveDefinition
            {
                directive_args.insert(
                    t.name.as_ref().map(|n| n.value.clone()).unwrap_or_default(),
                    t.arguments.iter().map(|a| a.name.value.clone()).collect(),
                );
            }
        }
        KnownArgumentNames { directive_args }
    }
}
impl<'a> Rule<'a> for KnownArgumentNames {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        match n {
            N::Directive(d, _) => {
                if let Some(known) = self.directive_args.get(&d.name.value) {
                    for a in &d.arguments {
                        if !known.contains(&a.name.value) {
                            let opts: Vec<&str> = known.iter().map(String::as_str).collect();
                            cx.report(GraphQLError::new(
                                format!(
                                    "Unknown argument '{}' on directive '@{}'.{}",
                                    a.name.value,
                                    d.name.value,
                                    did_you_mean_with(&suggestion_list(&a.name.value, &opts), None)
                                ),
                                vec![a.pos],
                            ));
                        }
                    }
                }
                Flow::Skip
            }
            N::Argument(a) => {
                if cx.ti.argument.is_none()
                    && let (Some(fd), Some(parent)) =
                        (cx.ti.get_field_def(), cx.ti.get_parent_type())
                {
                    let def = cx.schema.field_def(fd);
                    let opts: Vec<&str> = def.args.iter().map(|x| x.name.as_str()).collect();
                    // `args[3][-1]` is the field the argument is on.
                    cx.report(GraphQLError::new(
                        format!(
                            "Unknown argument '{}' on field '{}.{}'.{}",
                            a.name.value,
                            cx.schema.t(parent).name,
                            current_field_name(cx),
                            did_you_mean_with(&suggestion_list(&a.name.value, &opts), None)
                        ),
                        vec![a.pos],
                    ));
                }
                Flow::Continue
            }
            _ => Flow::Continue,
        }
    }
}

/// The name of the field whose argument is being visited. The type info
/// only knows its definition, which is enough: the visitor reports the
/// node's own name, and an unknown argument is only reported when the
/// field is known.
fn current_field_name(cx: &Ctx<'_>) -> String {
    cx.ti
        .get_field_def()
        .map(|fd| cx.schema.field_def(fd).name.clone())
        .unwrap_or_default()
}

struct UniqueArgumentNames;
impl UniqueArgumentNames {
    fn check(cx: &mut Ctx<'_>, args: &[Argument]) {
        let mut groups: Vec<(&str, Vec<usize>)> = Vec::new();
        for a in args {
            match groups.iter_mut().find(|(k, _)| *k == a.name.value) {
                Some(g) => g.1.push(a.name.pos),
                None => groups.push((&a.name.value, vec![a.name.pos])),
            }
        }
        for (name, nodes) in groups {
            if nodes.len() > 1 {
                cx.report(GraphQLError::new(
                    format!("There can be only one argument named '{name}'."),
                    nodes,
                ));
            }
        }
    }
}
impl<'a> Rule<'a> for UniqueArgumentNames {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        match n {
            N::Field(f) => Self::check(cx, &f.arguments),
            N::Directive(d, _) => Self::check(cx, &d.arguments),
            _ => {}
        }
        Flow::Continue
    }
}

struct ValuesOfCorrectType;
impl<'a> Rule<'a> for ValuesOfCorrectType {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        let N::Value(v) = n else {
            return Flow::Continue;
        };
        let t = match v {
            ValueNode::List(_, _) => cx.ti.get_parent_input_type().cloned(),
            _ => cx.ti.get_input_type().cloned(),
        };
        if let Some(t) = t {
            let mut errs: Vec<GraphQLError> = Vec::new();
            let mut path = Vec::new();
            cx.coercer
                .validate_input_literal(v, &t, None, &mut path, &mut |e, _| {
                    errs.push(e);
                    true
                });
            for e in errs {
                cx.report(e);
            }
        }
        Flow::Skip
    }
}

struct ProvidedRequiredArguments {
    directive_required: HashMap<String, Vec<(String, String)>>,
}
impl ProvidedRequiredArguments {
    fn new(s: &Schema, doc: &Document) -> Self {
        let mut directive_required: HashMap<String, Vec<(String, String)>> = s
            .directives
            .iter()
            .map(|d| {
                (
                    d.name.clone(),
                    d.args
                        .iter()
                        .filter(|a| is_required(a))
                        .map(|a| (a.name.clone(), s.type_str(&a.type_)))
                        .collect(),
                )
            })
            .collect();
        for d in &doc.definitions {
            if let Definition::TypeSystem(t) = d
                && t.kind == TypeSystemKind::DirectiveDefinition
            {
                directive_required.insert(
                    t.name.as_ref().map(|n| n.value.clone()).unwrap_or_default(),
                    t.arguments
                        .iter()
                        .filter(|a| {
                            matches!(a.type_, Type::NonNull(_, _)) && a.default_value.is_none()
                        })
                        .map(|a| (a.name.value.clone(), print_type(&a.type_)))
                        .collect(),
                );
            }
        }
        ProvidedRequiredArguments { directive_required }
    }
}
impl<'a> Rule<'a> for ProvidedRequiredArguments {
    fn leave(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) {
        match n {
            N::Directive(d, _) => {
                if let Some(req) = self.directive_required.get(&d.name.value) {
                    for (name, ts) in req {
                        if !d.arguments.iter().any(|a| a.name.value == *name) {
                            cx.report(GraphQLError::new(
                                format!(
                                    "Argument '@{}({name}:)' of type '{ts}' is required, but it was not provided.",
                                    d.name.value
                                ),
                                vec![d.pos],
                            ));
                        }
                    }
                }
            }
            N::Field(f) => {
                let Some(fd) = cx.ti.get_field_def() else {
                    return;
                };
                let s = cx.schema;
                let def = s.field_def(fd);
                for a in &def.args {
                    if !f.arguments.iter().any(|x| x.name.value == a.name) && is_required(a) {
                        let ft = cx.ti.get_type().map(TypeRef::named);
                        let parent_str = if ft.is_some_and(|t| {
                            crate::schema::INTROSPECTION_TYPES.contains(&s.t(t).name.as_str())
                        }) {
                            "<meta>.".to_owned()
                        } else {
                            match cx.ti.get_parent_type() {
                                Some(p) => format!("{}.", s.t(p).name),
                                None => String::new(),
                            }
                        };
                        cx.report(GraphQLError::new(
                            format!(
                                "Argument '{parent_str}{}({}:)' of type '{}' is required, but it was not provided.",
                                f.name.value,
                                a.name,
                                s.type_str(&a.type_)
                            ),
                            vec![f.pos],
                        ));
                    }
                }
            }
            _ => {}
        }
    }
}

#[derive(Default)]
struct VariablesInAllowedPosition<'a> {
    var_defs: HashMap<String, &'a VariableDefinition>,
}
impl<'a> Rule<'a> for VariablesInAllowedPosition<'a> {
    fn enter(&mut self, _cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        if let N::Operation(o) = n {
            self.var_defs.clear();
            for v in &o.variable_definitions {
                self.var_defs.insert(v.variable.name.value.clone(), v);
            }
        }
        Flow::Continue
    }
    fn leave(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) {
        let N::Operation(o) = n else { return };
        let s = cx.schema;
        for u in cx.get_recursive_variable_usages(o) {
            let name = &u.node.name.value;
            let (Some(vd), Some(loc_t)) = (self.var_defs.get(name), &u.type_) else {
                continue;
            };
            let Some(var_t) = s.type_from_ast(&vd.type_) else {
                continue;
            };
            let allowed = if loc_t.is_non_null() && !var_t.is_non_null() {
                let has_var_default = vd
                    .default_value
                    .as_ref()
                    .is_some_and(|d| !matches!(d, ValueNode::Null(_)));
                if !has_var_default && !u.has_default {
                    false
                } else {
                    s.is_type_sub_type_of(&var_t, loc_t.nullable())
                }
            } else {
                s.is_type_sub_type_of(&var_t, loc_t)
            };
            if !allowed {
                cx.report(GraphQLError::new(
                    format!(
                        "Variable '${name}' of type '{}' used in position expecting type '{}'.",
                        s.type_str(&var_t),
                        s.type_str(loc_t)
                    ),
                    vec![vd.pos, u.node.pos],
                ));
            }
        }
    }
}

#[derive(Default)]
struct UniqueInputFieldNames {
    stack: Vec<HashMap<String, usize>>,
    known: HashMap<String, usize>,
}
impl<'a> Rule<'a> for UniqueInputFieldNames {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        match n {
            N::Value(ValueNode::Object(_, _)) => {
                self.stack.push(std::mem::take(&mut self.known));
            }
            N::ObjectField(f) => {
                let name = &f.name.value;
                if let Some(&prev) = self.known.get(name) {
                    cx.report(GraphQLError::new(
                        format!("There can be only one input field named '{name}'."),
                        vec![prev, f.name.pos],
                    ));
                } else {
                    self.known.insert(name.clone(), f.name.pos);
                }
            }
            _ => {}
        }
        Flow::Continue
    }
    fn leave(&mut self, _cx: &mut Ctx<'a>, n: &N<'a>) {
        if let N::Value(ValueNode::Object(_, _)) = n {
            self.known = self.stack.pop().unwrap_or_default();
        }
    }
}

struct MaxIntrospectionDepth;

/// `_check_depth()`'s walk: the fragments on the current path, the Python
/// frames it is using, and whether it ran out of them.
///
/// graphql-core re-checks a fragment once per path to it, so a fragment
/// that spreads the next one twice, 40 deep, means 2^40 checks and a
/// thread that never finishes. `memo` remembers fragments found not deep
/// enough at a depth, with the frames their check needed, and the walk
/// reuses that answer where it cannot differ: when no fragment below was
/// skipped for being on the path already (`cycle`), and when the frames it
/// needed still fit under the limit.
struct DepthWalk {
    visited: Vec<String>,
    frames: usize,
    limit: usize,
    overflow: bool,
    memo: HashMap<(String, usize), usize>,
    max_frames: usize,
    cycle: bool,
}

impl DepthWalk {
    /// A `_check_depth()` call: false past the frame limit, which is
    /// graphql-core's `RecursionError`.
    fn call(&mut self) -> bool {
        self.frames += 1;
        self.max_frames = self.max_frames.max(self.frames);
        if self.frames > self.limit {
            self.overflow = true;
        }
        !self.overflow
    }
}

impl MaxIntrospectionDepth {
    /// `_check_depth(sel)`, one Python frame, plus one for the fragment
    /// definition a spread is checked through.
    fn check(cx: &Ctx<'_>, sel: &Selection, depth: usize, w: &mut DepthWalk) -> bool {
        if !w.call() {
            return false;
        }
        let r = match sel {
            Selection::FragmentSpread(fs) => {
                let name = &fs.name.value;
                match cx.get_fragment(name) {
                    Some(f) if !w.visited.contains(name) => {
                        let key = (name.clone(), depth);
                        match w.memo.get(&key) {
                            Some(&needed) if w.frames + needed <= w.limit => false,
                            _ => {
                                let (outer_max, outer_cycle) = (w.max_frames, w.cycle);
                                let start = w.frames;
                                w.max_frames = w.frames;
                                w.cycle = false;
                                w.visited.push(name.clone());
                                let r = w.call() && Self::check_set(cx, &f.selection_set, depth, w);
                                w.frames -= 1;
                                w.visited.pop();
                                if !r && !w.overflow && !w.cycle {
                                    w.memo.insert(key, w.max_frames - start);
                                }
                                w.max_frames = w.max_frames.max(outer_max);
                                w.cycle |= outer_cycle;
                                r
                            }
                        }
                    }
                    Some(_) => {
                        w.cycle = true;
                        false
                    }
                    None => false,
                }
            }
            Selection::Field(f) => {
                let mut depth = depth;
                let mut reached = false;
                if matches!(
                    f.name.value.as_str(),
                    "fields" | "interfaces" | "possibleTypes" | "inputFields"
                ) {
                    depth += 1;
                    reached = depth >= 3;
                }
                if reached {
                    true
                } else {
                    match &f.selection_set {
                        Some(ss) => Self::check_set(cx, ss, depth, w),
                        None => false,
                    }
                }
            }
            Selection::InlineFragment(i) => Self::check_set(cx, &i.selection_set, depth, w),
        };
        w.frames -= 1;
        r
    }

    fn check_set(cx: &Ctx<'_>, ss: &SelectionSet, depth: usize, w: &mut DepthWalk) -> bool {
        ss.selections
            .iter()
            .any(|s| Self::check(cx, s, depth, w) || w.overflow)
            && !w.overflow
    }
}
impl<'a> Rule<'a> for MaxIntrospectionDepth {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        if let N::Field(f) = n
            && matches!(f.name.value.as_str(), "__schema" | "__type")
        {
            // _check_depth(node) on the field itself is the first frame.
            let mut w = DepthWalk {
                visited: Vec::new(),
                frames: 1,
                limit: cx.py_frames,
                overflow: false,
                memo: HashMap::new(),
                max_frames: 1,
                cycle: false,
            };
            let deep = match &f.selection_set {
                Some(ss) => Self::check_set(cx, ss, 0, &mut w),
                None => false,
            };
            if w.overflow {
                cx.recursion_error = true;
                return Flow::Skip;
            }
            if deep {
                cx.report(GraphQLError::new(
                    "Maximum introspection depth exceeded",
                    vec![f.pos],
                ));
                return Flow::Skip;
            }
        }
        Flow::Continue
    }
}

// ---- helpers for the cost validator and execution ----

/// `get_argument_values()`: the coerced arguments, or the error it
/// raises.
pub(crate) fn get_argument_values(
    coercer: &Coercer<'_>,
    args: &[crate::schema::InputValue],
    node_args: &[Argument],
    node_pos: usize,
    vars: Option<&crate::coerce::Variables>,
) -> Result<Vec<(String, Value)>, GraphQLError> {
    let mut out: Vec<(String, Value)> = Vec::new();
    for def in args {
        let arg = node_args.iter().rev().find(|a| a.name.value == def.name);
        let Some(arg) = arg else {
            if is_required(def) {
                return Err(GraphQLError::new(
                    format!(
                        "Argument '{}' of required type '{}' was not provided.",
                        def.name,
                        coercer.schema.type_str(&def.type_)
                    ),
                    vec![node_pos],
                ));
            }
            use_default(coercer, def, node_pos, &mut out)?;
            continue;
        };
        if let ValueNode::Variable(v) = &arg.value
            && vars.is_none_or(|m| !m.contains_key(&v.name.value))
            && !is_required(def)
        {
            use_default(coercer, def, node_pos, &mut out)?;
            continue;
        }
        match coercer.input_literal(&arg.value, &def.type_, vars) {
            Some(v) => out.push((def.name.clone(), v)),
            None => {
                let mut raised: Option<GraphQLError> = None;
                let mut path = Vec::new();
                coercer.validate_input_literal(
                    &arg.value,
                    &def.type_,
                    vars,
                    &mut path,
                    &mut |mut e, p| {
                        e.message = format!(
                            "Argument '{}' has invalid value{}: {}",
                            def.name,
                            print_path_list(p),
                            e.message
                        );
                        raised = Some(e);
                        false
                    },
                );
                return Err(raised.unwrap_or_else(|| {
                    GraphQLError::new("Invalid argument", vec![arg.value.pos()])
                }));
            }
        }
    }
    Ok(out)
}

fn use_default(
    coercer: &Coercer<'_>,
    def: &crate::schema::InputValue,
    node_pos: usize,
    out: &mut Vec<(String, Value)>,
) -> Result<(), GraphQLError> {
    match coercer.default_value(def) {
        Ok(Some(v)) => out.push((def.name.clone(), v)),
        Ok(None) => {}
        Err(_) => {
            return Err(GraphQLError::new(
                format!("Argument '{}' has invalid default value.", def.name),
                vec![node_pos],
            ));
        }
    }
    Ok(())
}

use crate::value::Value;

/// Fragment chains against graphql-core: where each rule that follows
/// spreads runs out of Python frames.
#[cfg(test)]
mod recursion_tests {
    use super::*;
    use crate::coerce::ScalarError;

    struct Scalars;
    impl ScalarParsers for Scalars {
        fn parse_value(&self, _: &str, v: &Value) -> Result<Value, ScalarError> {
            Ok(v.clone())
        }
    }

    const SDL: &str = "type Query { a: Obj }\ntype Obj { x: Int }\n";

    fn chain(n: usize, on: &str, leaf: &str, body: &dyn Fn(usize) -> String) -> String {
        let mut s = String::new();
        for i in 0..n {
            s.push_str(&format!("fragment F{i} on {on}{{{}}}\n", body(i)));
        }
        s.push_str(&format!("fragment F{n} on {on}{{{leaf}}}\n"));
        s
    }

    fn spread(i: usize) -> String {
        format!("...F{}", i + 1)
    }

    /// `Err` is the `RecursionError`.
    fn run(schema: &Schema, doc: &str, frames: usize) -> Result<usize, ()> {
        let body: Vec<char> = doc.chars().collect();
        let d = crate::parser::parse(&body).expect("parses");
        validate_with_frames(schema, &Scalars, &d, &body, Some(2500), frames, None).map(|e| e.len())
    }

    /// Whether a chain of `n` is the shortest that is a `RecursionError`
    /// (each rule's frame count grows with the chain).
    fn first_fails_at(
        schema: &Schema,
        frames: usize,
        mk: &dyn Fn(usize) -> String,
        n: usize,
    ) -> bool {
        run(schema, &mk(n - 1), frames).is_ok() && run(schema, &mk(n), frames).is_err()
    }

    /// On the daemon's 8 MiB worker stack.
    fn on_big_stack(f: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(8 << 20)
            .spawn(f)
            .expect("thread")
            .join()
            .expect("no panic");
    }

    /// Each fragment spreading the next twice, 60 deep, is 2^60 paths for
    /// graphql-core's introspection depth check. It must finish quickly
    /// with graphql-core's answer, and still find a deep path at the end.
    #[test]
    fn introspection_depth_with_doubled_spreads_is_not_exponential() {
        on_big_stack(|| {
            let schema = Schema::from_sdl(SDL);
            let twice = |i: usize| format!("...F{} ...F{}", i + 1, i + 1);
            let shallow = format!(
                "query{{__schema{{...F0}}}}\n{}",
                chain(60, "__Schema", "description", &twice)
            );
            let started = std::time::Instant::now();
            assert_eq!(run(&schema, &shallow, 969), Ok(0));
            assert!(started.elapsed() < std::time::Duration::from_secs(5));
            let deep = format!(
                "query{{__schema{{...F0}}}}\n{}",
                chain(
                    60,
                    "__Schema",
                    "types{fields{type{fields{type{fields{name}}}}}}",
                    &twice
                )
            );
            // The same answer as a single chain, which graphql-core walks
            // without repeats.
            let once = |i: usize| format!("...F{}", i + 1);
            let single = format!(
                "query{{__schema{{...F0}}}}\n{}",
                chain(
                    60,
                    "__Schema",
                    "types{fields{type{fields{type{fields{name}}}}}}",
                    &once
                )
            );
            assert_eq!(run(&schema, &deep, 969), run(&schema, &single, 969));
            assert!(run(&schema, &deep, 969).is_ok_and(|n| n >= 1));
        });
    }

    /// The shortest failing chains graphql-core 3.3.0 and ariadne 1.1.1
    /// give on Python 3.13 with 993 frames to spare above the rule method
    /// (a bare `validate()` call), and the same at v4's 969.
    #[test]
    fn fragment_chains_fail_where_graphql_core_does() {
        on_big_stack(|| {
            let schema = Schema::from_sdl(SDL);
            let s = &schema;
            let q = |n| chain(n, "Query", "__typename", &spread);
            let used = |n| format!("query{{...F0}}\n{}", q(n));
            let used_after = |n| format!("{}query{{...F0}}\n", q(n));
            let unused = |n| format!("query{{__typename}}\n{}", q(n));
            let unused_before = |n| format!("{}query{{__typename}}\n", q(n));
            let two_heads = |n: usize| format!("query{{...F0 ...F{}}}\n{}", n / 2, q(n));
            let inline = |i: usize| format!("...on Query{{...F{}}}", i + 1);
            let inline_used = |n| {
                format!(
                    "query{{...F0}}\n{}",
                    chain(n, "Query", "__typename", &inline)
                )
            };
            let inline_unused = |n| {
                format!(
                    "query{{__typename}}\n{}",
                    chain(n, "Query", "__typename", &inline)
                )
            };
            let intro = |n| {
                format!(
                    "query{{__schema{{...F0}}}}\n{}",
                    chain(n, "__Schema", "description", &spread)
                )
            };
            let intro_inline = |n| {
                let body = |i: usize| format!("...on __Schema{{...F{}}}", i + 1);
                format!(
                    "query{{__schema{{...F0}}}}\n{}",
                    chain(n, "__Schema", "description", &body)
                )
            };
            // The cost validator: two frames per spread.
            assert!(first_fails_at(s, 993, &used, 496));
            assert!(first_fails_at(s, 993, &used_after, 496));
            assert!(first_fails_at(s, 993, &two_heads, 496));
            assert!(first_fails_at(s, 993, &inline_used, 331));
            // OverlappingFieldsCanBeMerged, from each fragment definition.
            assert!(first_fails_at(s, 993, &unused, 987));
            assert!(first_fails_at(s, 993, &unused_before, 987));
            // graphql-core: 986, two more __hash__ frames in its deepest
            // lookup.
            assert!(first_fails_at(s, 993, &inline_unused, 987));
            // Subscriptions: the cost validator follows spreads, but not
            // fields (no subscription type); then OverlappingFields.
            let sub = |n| format!("subscription{{...F0}}\n{}", q(n));
            let sub_field = |n| format!("subscription{{a{{...F0}}}}\n{}", q(n));
            assert!(first_fails_at(s, 993, &sub, 496));
            assert!(first_fails_at(s, 993, &sub_field, 986));
            // MaxIntrospectionDepth: the cost validator skips __schema.
            assert!(first_fails_at(s, 993, &intro, 495));
            assert!(first_fails_at(s, 993, &intro_inline, 330));
            // In v4.
            assert!(first_fails_at(s, PY_STACK_FRAMES, &used, 484));
            assert!(first_fails_at(s, PY_STACK_FRAMES, &unused, 963));
        });
    }

    /// NoFragmentCycles on its own: a frame per fragment on the path and
    /// one for get_fragment_spreads().
    #[test]
    fn no_fragment_cycles_counts_frames() {
        on_big_stack(|| {
            let schema = Schema::from_sdl(SDL);
            let doc = |n| chain(n, "Query", "__typename", &spread);
            let check = |n: usize, frames: usize| {
                let text = doc(n);
                let body: Vec<char> = text.chars().collect();
                let d = crate::parser::parse(&body).expect("parses");
                let mut cx = Ctx {
                    schema: &schema,
                    body: &body,
                    coercer: Coercer {
                        schema: &schema,
                        scalars: &Scalars,
                    },
                    ti: TypeInfo::default(),
                    errors: Vec::new(),
                    aborted: false,
                    in_sdl: false,
                    recursion_error: false,
                    py_frames: frames,
                    fragments: d
                        .definitions
                        .iter()
                        .filter_map(|x| match x {
                            Definition::Fragment(f) => Some((f.name.value.as_str(), f)),
                            _ => None,
                        })
                        .collect(),
                };
                let Some(Definition::Fragment(f0)) = d.definitions.first() else {
                    unreachable!()
                };
                NoFragmentCycles::default().detect(&mut cx, f0);
                !cx.recursion_error
            };
            // F0..Fn: n + 1 calls, then get_fragment_spreads() in Fn.
            assert!(check(991, 993));
            assert!(!check(992, 993));
            assert!(check(20_000, 20_002));
            assert!(!check(20_000, 20_001));
        });
    }

    /// Cycles are still reported, along every path, as before.
    #[test]
    fn fragment_cycles_are_reported() {
        let schema = Schema::from_sdl(SDL);
        let doc = "query{...A}\nfragment A on Query{...B ...C}\nfragment B on Query{...A}\nfragment C on Query{...C ...B}\n";
        // The cost validator recurses through the cycle: RecursionError.
        assert_eq!(run(&schema, doc, PY_STACK_FRAMES), Err(()));
        let body: Vec<char> = doc.chars().collect();
        let d = crate::parser::parse(&body).expect("parses");
        let errors =
            validate_with_frames(&schema, &Scalars, &d, &body, None, PY_STACK_FRAMES, None)
                .expect("no RecursionError without the cost validator");
        let messages: Vec<&str> = errors.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(
            messages,
            [
                "Cannot spread fragment 'A' within itself via 'B'.",
                "Cannot spread fragment 'C' within itself.",
            ]
        );
    }
}
