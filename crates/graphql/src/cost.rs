//! ariadne's `cost_validator(maximum_cost, default_cost=1)` as IRRd
//! configures it: no cost map and no `@cost` directives, so every field
//! costs 1 plus the cost of its selections.
//!
//! It computes field arguments without variables, so a variable in a
//! non-null argument makes `get_argument_values()` raise, and ariadne
//! reports `str(error)` (the message with its source location printed)
//! as a validation error. IRRd 4.5.4 behaves exactly so, and irrd-ng does
//! too.

use std::collections::HashMap;

use crate::ast::*;
use crate::error::GraphQLError;
use crate::schema::{Kind, TypeId};
use crate::validation::{Ctx, Flow, N, Rule, get_argument_values};
use crate::value::Value;

pub(crate) struct CostValidator {
    maximum: i64,
    cost: i64,
    fragment_costs: HashMap<(String, Option<String>), i64>,
    /// Fragments whose cost is being computed: a cycle recurses until
    /// Python's recursion limit.
    in_progress: Vec<String>,
}

impl CostValidator {
    pub(crate) fn new(maximum: i64) -> Self {
        CostValidator {
            maximum,
            cost: 0,
            fragment_costs: HashMap::new(),
            in_progress: Vec::new(),
        }
    }

    fn node_cost<'a>(&mut self, cx: &mut Ctx<'a>, set: Option<&'a SelectionSet>, t: Option<TypeId>) -> i64 {
        let Some(set) = set else { return 0 };
        let s = cx.schema;
        let fields_of = |t: Option<TypeId>| -> Option<TypeId> {
            t.filter(|t| matches!(s.t(*t).kind, Kind::Object | Kind::Interface))
        };
        let ft = fields_of(t);
        let mut total = 0i64;
        for sel in &set.selections {
            let mut node_cost = 1i64;
            match sel {
                Selection::Field(f) => {
                    let Some(owner) = ft else { continue };
                    let Some(def) = s.t(owner).field(&f.name.value) else {
                        continue;
                    };
                    let field_type = def.type_.named();
                    if let Err(e) =
                        get_argument_values(&cx.coercer, &def.args, &f.arguments, f.pos, None)
                    {
                        let msg = e.to_str(cx.body);
                        cx.report_pub(GraphQLError::plain(msg));
                    }
                    node_cost += self.node_cost(cx, f.selection_set.as_ref(), Some(field_type));
                }
                Selection::FragmentSpread(fs) => {
                    if let Some(frag) = cx.fragments_get(&fs.name.value) {
                        let ftype = s.type_id(&frag.type_condition.name.value);
                        node_cost = self.fragment_cost(cx, frag, ftype);
                    }
                }
                Selection::InlineFragment(i) => {
                    let it = match &i.type_condition {
                        Some(tc) => s.type_id(&tc.name.value),
                        None => t,
                    };
                    node_cost = self.node_cost(cx, Some(&i.selection_set), it);
                }
            }
            total += node_cost;
        }
        total
    }

    fn fragment_cost<'a>(
        &mut self,
        cx: &mut Ctx<'a>,
        frag: &'a FragmentDefinition,
        t: Option<TypeId>,
    ) -> i64 {
        let key = (
            frag.name.value.clone(),
            t.map(|t| cx.schema.t(t).name.clone()),
        );
        if let Some(c) = self.fragment_costs.get(&key) {
            return *c;
        }
        if self.in_progress.contains(&frag.name.value) {
            // RecursionError in v4: the request fails with a 500.
            cx.recursion_error = true;
            return 0;
        }
        self.in_progress.push(frag.name.value.clone());
        // ariadne computes it twice, at multiplier 1 and 2; without cost
        // directives both are the same, but errors are reported twice.
        let at_one = self.node_cost(cx, Some(&frag.selection_set), t);
        let _at_two = self.node_cost(cx, Some(&frag.selection_set), t);
        self.in_progress.pop();
        self.fragment_costs.insert(key, at_one);
        at_one
    }
}

impl<'a> Rule<'a> for CostValidator {
    fn enter(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) -> Flow {
        if let N::Operation(o) = n {
            let t = cx.schema.root_type(o.operation);
            self.cost += self.node_cost(cx, Some(&o.selection_set), t);
        }
        Flow::Continue
    }

    fn leave(&mut self, cx: &mut Ctx<'a>, n: &N<'a>) {
        if let N::Operation(_) = n
            && self.cost > self.maximum
        {
            let mut e = GraphQLError::plain(format!(
                "The query exceeds the maximum cost of {}. Actual cost is {}",
                self.maximum, self.cost
            ));
            e.extensions = Some(Value::Object(vec![(
                "cost".into(),
                Value::Object(vec![
                    ("requestedQueryCost".into(), Value::Int(i128::from(self.cost))),
                    ("maximumAvailable".into(), Value::Int(i128::from(self.maximum))),
                ]),
            )]));
            cx.report_pub(e);
        }
    }
}
