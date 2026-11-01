//! `OverlappingFieldsCanBeMergedRule`, ported from graphql-core 3.3
//! including its caches, which decide which conflicts are reported when a
//! document has several.

use std::collections::HashMap;

use crate::ast::*;
use crate::error::{GraphQLError, print_value};
use crate::schema::{Kind, Schema, TypeId, TypeRef};
use crate::suggest::natural_cmp;
use crate::validation::{Ctx, Flow, N, Rule};

const MAX_FIELD_COMPARISONS: usize = 250_000;

#[derive(Debug)]
struct BudgetExceeded;

/// `(parent_type, node, def_type)`; `def_type` is `None` when the field
/// has no definition.
type NodeAndDef<'a> = (Option<TypeId>, &'a Field, Option<TypeRef>);
type FieldMap<'a> = Vec<(String, Vec<NodeAndDef<'a>>)>;

#[derive(Debug, Clone)]
enum ReasonMsg {
    Text(String),
    Sub(Vec<(String, ReasonMsg)>),
}

type Conflict = ((String, ReasonMsg), Vec<usize>, Vec<usize>);

#[derive(Clone)]
struct Spread<'a> {
    key: String,
    node: &'a FragmentSpread,
}

/// Field maps and spreads per selection set (by address).
type Cache<'a> = HashMap<usize, (std::rc::Rc<FieldMap<'a>>, Vec<Spread<'a>>)>;

#[derive(Default)]
pub(crate) struct OverlappingFields<'a> {
    cache: Cache<'a>,
    /// `OrderedPairSet`: by field map (its selection set) and fragment key.
    compared_fields_fragments: HashMap<usize, HashMap<String, bool>>,
    comparisons: usize,
    /// `PairSet`
    compared_fragments: HashMap<String, HashMap<String, bool>>,
    budget_exceeded: bool,
}

fn reason_message(r: &ReasonMsg) -> String {
    match r {
        ReasonMsg::Text(t) => t.clone(),
        ReasonMsg::Sub(list) => list
            .iter()
            .map(|(name, sub)| {
                format!(
                    "subfields '{name}' conflict because {}",
                    reason_message(sub)
                )
            })
            .collect::<Vec<_>>()
            .join(" and "),
    }
}

/// `sort_value_node()` then `print_ast()`.
fn stringify(v: &ValueNode) -> String {
    fn sort(v: &ValueNode) -> ValueNode {
        match v {
            ValueNode::Object(p, fields) => {
                let mut fs: Vec<ObjectField> = fields
                    .iter()
                    .map(|f| ObjectField {
                        pos: f.pos,
                        name: f.name.clone(),
                        value: sort(&f.value),
                    })
                    .collect();
                fs.sort_by(|a, b| natural_cmp(&a.name.value, &b.name.value));
                ValueNode::Object(*p, fs)
            }
            ValueNode::List(p, items) => ValueNode::List(*p, items.iter().map(sort).collect()),
            n => n.clone(),
        }
    }
    print_value(&sort(v))
}

fn same_arguments(a1: &[Argument], a2: &[Argument]) -> bool {
    if a1.is_empty() {
        return a2.is_empty();
    }
    if a2.is_empty() || a1.len() != a2.len() {
        return false;
    }
    let values2: HashMap<&str, &ValueNode> = a2
        .iter()
        .map(|a| (a.name.value.as_str(), &a.value))
        .collect();
    a1.iter().all(|a| match values2.get(a.name.value.as_str()) {
        None => false,
        Some(v2) => stringify(&a.value) == stringify(v2),
    })
}

fn same_streams(d1: &[Directive], d2: &[Directive]) -> bool {
    let s1 = d1.iter().find(|d| d.name.value == "stream");
    let s2 = d2.iter().find(|d| d.name.value == "stream");
    match (s1, s2) {
        (None, None) => true,
        (Some(a), Some(b)) => same_arguments(&a.arguments, &b.arguments),
        _ => false,
    }
}

fn do_types_conflict(s: &Schema, t1: &TypeRef, t2: &TypeRef) -> bool {
    match (t1, t2) {
        (TypeRef::List(a), TypeRef::List(b)) => do_types_conflict(s, a, b),
        (TypeRef::List(_), _) | (_, TypeRef::List(_)) => true,
        (TypeRef::NonNull(a), TypeRef::NonNull(b)) => do_types_conflict(s, a, b),
        (TypeRef::NonNull(_), _) | (_, TypeRef::NonNull(_)) => true,
        (TypeRef::Named(a), TypeRef::Named(b)) => {
            if s.t(*a).is_leaf() || s.t(*b).is_leaf() {
                a != b
            } else {
                false
            }
        }
    }
}

impl<'a> OverlappingFields<'a> {
    fn fields_and_spreads(
        &mut self,
        cx: &Ctx<'a>,
        parent: Option<TypeId>,
        set: &'a SelectionSet,
    ) -> (std::rc::Rc<FieldMap<'a>>, Vec<Spread<'a>>) {
        let key = set as *const _ as usize;
        if let Some(c) = self.cache.get(&key) {
            return c.clone();
        }
        let mut fm: FieldMap<'a> = Vec::new();
        let mut spreads: Vec<Spread<'a>> = Vec::new();
        collect(cx, parent, set, &mut fm, &mut spreads);
        let v = (std::rc::Rc::new(fm), spreads);
        self.cache.insert(key, v.clone());
        v
    }

    fn referenced(
        &mut self,
        cx: &Ctx<'a>,
        f: &'a FragmentDefinition,
    ) -> (std::rc::Rc<FieldMap<'a>>, Vec<Spread<'a>>) {
        let key = &f.selection_set as *const _ as usize;
        if let Some(c) = self.cache.get(&key) {
            return c.clone();
        }
        let t = cx.schema.type_id(&f.type_condition.name.value);
        self.fields_and_spreads(cx, t, &f.selection_set)
    }

    fn within_selection_set(
        &mut self,
        cx: &Ctx<'a>,
        parent: Option<TypeId>,
        set: &'a SelectionSet,
    ) -> Result<Vec<Conflict>, BudgetExceeded> {
        let mut conflicts = Vec::new();
        let (fm, spreads) = self.fields_and_spreads(cx, parent, set);
        let fm_key = set as *const _ as usize;
        self.collect_within(cx, &mut conflicts, &fm)?;
        for (i, sp) in spreads.iter().enumerate() {
            self.between_fields_and_fragment(cx, &mut conflicts, false, &fm, fm_key, sp)?;
            for other in &spreads[i + 1..] {
                self.between_fragments(cx, &mut conflicts, false, sp, other)?;
            }
        }
        Ok(conflicts)
    }

    fn between_fields_and_fragment(
        &mut self,
        cx: &Ctx<'a>,
        conflicts: &mut Vec<Conflict>,
        excl: bool,
        fm: &FieldMap<'a>,
        fm_key: usize,
        sp: &Spread<'a>,
    ) -> Result<(), BudgetExceeded> {
        if let Some(m) = self.compared_fields_fragments.get(&fm_key)
            && let Some(&r) = m.get(&sp.key)
            && (excl || excl == r)
        {
            return Ok(());
        }
        self.compared_fields_fragments
            .entry(fm_key)
            .or_default()
            .insert(sp.key.clone(), excl);
        let Some(frag) = cx.fragments_get(&sp.node.name.value) else {
            return Ok(());
        };
        let (fm2, refs) = self.referenced(cx, frag);
        let fm2_key = &frag.selection_set as *const _ as usize;
        if fm2_key == fm_key {
            return Ok(());
        }
        self.collect_between(cx, conflicts, excl, fm, &fm2)?;
        for r in &refs {
            self.between_fields_and_fragment(cx, conflicts, excl, fm, fm_key, r)?;
        }
        Ok(())
    }

    fn pair_has(&self, a: &str, b: &str, excl: bool) -> bool {
        let (k1, k2) = if a < b { (a, b) } else { (b, a) };
        match self.compared_fragments.get(k1).and_then(|m| m.get(k2)) {
            None => false,
            Some(&r) => excl || excl == r,
        }
    }

    fn pair_add(&mut self, a: &str, b: &str, excl: bool) {
        let (k1, k2) = if a < b { (a, b) } else { (b, a) };
        self.compared_fragments
            .entry(k1.to_owned())
            .or_default()
            .insert(k2.to_owned(), excl);
    }

    fn between_fragments(
        &mut self,
        cx: &Ctx<'a>,
        conflicts: &mut Vec<Conflict>,
        excl: bool,
        s1: &Spread<'a>,
        s2: &Spread<'a>,
    ) -> Result<(), BudgetExceeded> {
        if s1.key == s2.key {
            return Ok(());
        }
        if self.pair_has(&s1.key, &s2.key, excl) {
            return Ok(());
        }
        self.pair_add(&s1.key, &s2.key, excl);
        let (Some(f1), Some(f2)) = (
            cx.fragments_get(&s1.node.name.value),
            cx.fragments_get(&s2.node.name.value),
        ) else {
            return Ok(());
        };
        let (fm1, refs1) = self.referenced(cx, f1);
        let (fm2, refs2) = self.referenced(cx, f2);
        self.collect_between(cx, conflicts, excl, &fm1, &fm2)?;
        for r2 in &refs2 {
            self.between_fragments(cx, conflicts, excl, s1, r2)?;
        }
        for r1 in &refs1 {
            self.between_fragments(cx, conflicts, excl, r1, s2)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn between_sub_selection_sets(
        &mut self,
        cx: &Ctx<'a>,
        excl: bool,
        p1: Option<TypeId>,
        ss1: &'a SelectionSet,
        p2: Option<TypeId>,
        ss2: &'a SelectionSet,
    ) -> Result<Vec<Conflict>, BudgetExceeded> {
        let mut conflicts = Vec::new();
        let (fm1, sp1) = self.fields_and_spreads(cx, p1, ss1);
        let (fm2, sp2) = self.fields_and_spreads(cx, p2, ss2);
        let k1 = ss1 as *const _ as usize;
        let k2 = ss2 as *const _ as usize;
        self.collect_between(cx, &mut conflicts, excl, &fm1, &fm2)?;
        for s in &sp2 {
            self.between_fields_and_fragment(cx, &mut conflicts, excl, &fm1, k1, s)?;
        }
        for s in &sp1 {
            self.between_fields_and_fragment(cx, &mut conflicts, excl, &fm2, k2, s)?;
        }
        for a in &sp1 {
            for b in &sp2 {
                self.between_fragments(cx, &mut conflicts, excl, a, b)?;
            }
        }
        Ok(conflicts)
    }

    fn collect_within(
        &mut self,
        cx: &Ctx<'a>,
        conflicts: &mut Vec<Conflict>,
        fm: &FieldMap<'a>,
    ) -> Result<(), BudgetExceeded> {
        for (name, fields) in fm {
            if fields.len() > 1 {
                for i in 0..fields.len() {
                    for j in i + 1..fields.len() {
                        if let Some(c) =
                            self.find_conflict(cx, false, name, &fields[i], &fields[j])?
                        {
                            conflicts.push(c);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn collect_between(
        &mut self,
        cx: &Ctx<'a>,
        conflicts: &mut Vec<Conflict>,
        excl: bool,
        fm1: &FieldMap<'a>,
        fm2: &FieldMap<'a>,
    ) -> Result<(), BudgetExceeded> {
        for (name, f1s) in fm1 {
            let Some((_, f2s)) = fm2.iter().find(|(k, _)| k == name) else {
                continue;
            };
            for f1 in f1s {
                for f2 in f2s {
                    if let Some(c) = self.find_conflict(cx, excl, name, f1, f2)? {
                        conflicts.push(c);
                    }
                }
            }
        }
        Ok(())
    }

    fn find_conflict(
        &mut self,
        cx: &Ctx<'a>,
        parent_excl: bool,
        name: &str,
        f1: &NodeAndDef<'a>,
        f2: &NodeAndDef<'a>,
    ) -> Result<Option<Conflict>, BudgetExceeded> {
        self.comparisons += 1;
        if self.comparisons > MAX_FIELD_COMPARISONS {
            return Err(BudgetExceeded);
        }
        let s = cx.schema;
        let (p1, n1, t1) = f1;
        let (p2, n2, t2) = f2;
        let is_obj = |p: &Option<TypeId>| p.is_some_and(|t| s.t(t).kind == Kind::Object);
        let excl = parent_excl || (p1 != p2 && is_obj(p1) && is_obj(p2));
        let reason = |m: String| -> Option<Conflict> {
            Some((
                (name.to_owned(), ReasonMsg::Text(m)),
                vec![n1.pos],
                vec![n2.pos],
            ))
        };
        if !excl {
            if n1.name.value != n2.name.value {
                return Ok(reason(format!(
                    "'{}' and '{}' are different fields",
                    n1.name.value, n2.name.value
                )));
            }
            if !same_arguments(&n1.arguments, &n2.arguments) {
                return Ok(reason("they have differing arguments".to_owned()));
            }
        }
        if !same_streams(&n1.directives, &n2.directives) {
            return Ok(reason("they have differing stream directives".to_owned()));
        }
        if let (Some(a), Some(b)) = (t1, t2)
            && do_types_conflict(s, a, b)
        {
            return Ok(reason(format!(
                "they return conflicting types '{}' and '{}'",
                s.type_str(a),
                s.type_str(b)
            )));
        }
        if let (Some(ss1), Some(ss2)) = (&n1.selection_set, &n2.selection_set) {
            let c = self.between_sub_selection_sets(
                cx,
                excl,
                t1.as_ref().map(TypeRef::named),
                ss1,
                t2.as_ref().map(TypeRef::named),
                ss2,
            )?;
            if !c.is_empty() {
                let mut a = vec![n1.pos];
                let mut b = vec![n2.pos];
                let mut reasons = Vec::new();
                for (r, x, y) in c {
                    reasons.push(r);
                    a.extend(x);
                    b.extend(y);
                }
                return Ok(Some(((name.to_owned(), ReasonMsg::Sub(reasons)), a, b)));
            }
        }
        Ok(None)
    }
}

fn collect<'a>(
    cx: &Ctx<'a>,
    parent: Option<TypeId>,
    set: &'a SelectionSet,
    fm: &mut FieldMap<'a>,
    spreads: &mut Vec<Spread<'a>>,
) {
    let s = cx.schema;
    for sel in &set.selections {
        match sel {
            Selection::Field(f) => {
                let def = parent
                    .filter(|p| matches!(s.t(*p).kind, Kind::Object | Kind::Interface))
                    .and_then(|p| s.t(p).field(&f.name.value))
                    .map(|d| d.type_.clone());
                let key = f.response_key().to_owned();
                match fm.iter_mut().find(|(k, _)| *k == key) {
                    Some(e) => e.1.push((parent, f, def)),
                    None => fm.push((key, vec![(parent, f, def)])),
                }
            }
            Selection::FragmentSpread(fs) => {
                // Every fragment defined in the document has a (possibly
                // empty) signature, which adds "()" to the key.
                let mut key = fs.name.value.clone();
                if cx.fragments_get(&fs.name.value).is_some() {
                    key.push_str("()");
                }
                match spreads.iter_mut().find(|x| x.key == key) {
                    Some(e) => e.node = fs,
                    None => spreads.push(Spread { key, node: fs }),
                }
            }
            Selection::InlineFragment(i) => {
                let t = match &i.type_condition {
                    Some(tc) => s.type_id(&tc.name.value),
                    None => parent,
                };
                collect(cx, t, &i.selection_set, fm, spreads);
            }
        }
    }
}

impl<'a> Rule<'a> for OverlappingFields<'a> {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        let N::SelectionSet(ss) = n else {
            return Flow::Continue;
        };
        if self.budget_exceeded {
            return Flow::Continue;
        }
        let parent = cx.ti_parent_type();
        match self.within_selection_set(cx, parent, ss) {
            Err(BudgetExceeded) => {
                self.budget_exceeded = true;
                cx.report_pub(GraphQLError::new(
                    format!(
                        "Query is too complex to validate for overlapping fields: exceeded {MAX_FIELD_COMPARISONS} field comparisons. Validation was aborted."
                    ),
                    vec![ss.pos],
                ));
            }
            Ok(conflicts) => {
                for ((name, reason), f1, f2) in conflicts {
                    let mut pos = f1;
                    pos.extend(f2);
                    cx.report_pub(GraphQLError::new(
                        format!(
                            "Fields '{name}' conflict because {}. Use different aliases on the fields to fetch both if this was intentional.",
                            reason_message(&reason)
                        ),
                        pos,
                    ));
                }
            }
        }
        Flow::Continue
    }
}
