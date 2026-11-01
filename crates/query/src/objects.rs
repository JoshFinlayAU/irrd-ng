//! `RPSLDatabaseQuery` as the GraphQL resolvers build it: any combination
//! of filters, ANDed, answered from the store's indexes.
//!
//! v4 runs these queries with `enable_ordering=False`, so PostgreSQL
//! returns rows in whatever order its plan produces. irrd-ng returns them
//! in internal id order, which follows the order objects were stored in.

use std::collections::HashSet;

use rpsl::Ip;
use store::{ReadView, RoutePreferenceStatus, RpkiStatus, RpslObjectRef, ScopeFilterStatus};

use crate::resolver::{
    Found, IpBounds, QResult, QueryError, addr_u128, ilike, like_pattern, parsed_field,
    prefix_relation,
};
use crate::settings::QuerySettings;

/// An IP filter (`ip_exact()` and friends).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFilter {
    /// `ip_exact`
    Exact,
    /// `ip_less_specific`
    LessSpecific,
    /// `ip_more_specific`
    MoreSpecific,
    /// `ip_less_specific_one_level`
    LessSpecificOneLevel,
    /// `ip_any`
    Any,
}

/// A query being built, filter by filter, in v4's call order.
#[derive(Debug, Clone, Default)]
pub struct ObjectQuery {
    /// `rpsl_pks()`: upper-cased and stripped.
    pub rpsl_pks: Option<Vec<String>>,
    /// `object_classes()`, one list per call.
    pub classes: Vec<Vec<String>>,
    /// `asns_first()`
    pub asns_first: Option<Vec<i128>>,
    /// `text_search()`
    pub text_search: Option<String>,
    /// The AS number a text search parsed as, if it did.
    pub text_asn: Option<u32>,
    /// `rpki_status()`
    pub rpki: Option<Vec<RpkiStatus>>,
    /// `scopefilter_status()`
    pub scope: Option<Vec<ScopeFilterStatus>>,
    /// `route_preference_status()`
    pub routepref: Option<Vec<RoutePreferenceStatus>>,
    /// `sources()`: upper-cased and stripped.
    pub sources: Option<Vec<String>>,
    /// `lookup_attrs_in([attr], values)`, one per call.
    pub lookups: Vec<(String, Vec<String>)>,
    /// IP filters in call order.
    pub ip: Vec<(IpFilter, Ip)>,
    /// `limit()`
    pub limit: Option<i64>,
}

fn rpki_ok(list: &Option<Vec<RpkiStatus>>, o: &RpslObjectRef<'_>) -> bool {
    list.as_ref().is_none_or(|l| l.contains(&o.rpki_status))
}

impl ObjectQuery {
    /// `object_classes(classes)`
    pub fn object_classes(&mut self, classes: Vec<String>) {
        self.classes.push(classes);
    }

    /// `text_search(value)`: an AS number also restricts the classes
    /// (`object_classes([...]).asn_less_specific(asn)`).
    pub fn text_search(&mut self, value: &str, settings: &QuerySettings) {
        if let Ok((_, asn)) = rpsl::parse_as_number(value, false, true, settings.asdot_queries) {
            self.object_classes(vec!["as-block".into(), "as-set".into(), "aut-num".into()]);
            self.text_asn = Some(asn);
        }
        self.text_search = Some(value.to_owned());
    }

    /// Whether prefix searches use the `prefix` column
    /// (`_prefix_query_permitted()`).
    fn prefix_permitted(&self, settings: &QuerySettings) -> bool {
        settings.inetnum_search_disabled
            || self
                .classes
                .last()
                .is_some_and(|c| !c.is_empty() && !c.iter().any(|x| x == "inetnum"))
    }

    /// Run the query.
    pub fn execute<'t>(
        &self,
        view: &ReadView<'t>,
        settings: &QuerySettings,
    ) -> QResult<Vec<Found<'t>>> {
        let prefix_ok = self.prefix_permitted(settings);
        let one_level = self
            .ip
            .iter()
            .position(|(f, _)| *f == IpFilter::LessSpecificOneLevel);
        if one_level.is_some_and(|i| i + 1 < self.ip.len()) {
            // ip_less_specific_one_level() freezes the query.
            return Err(QueryError::Internal(
                "This query was frozen - no more filters can be applied.".to_owned(),
            ));
        }
        // Candidate ids from the most selective filter available.
        let mut lookup_sets: Vec<HashSet<u64>> = Vec::new();
        for (attr, values) in &self.lookups {
            let mut set = HashSet::new();
            for v in values {
                let v = rpsl::python::upper(v);
                set.extend(view.ids_by_lookup(attr, Some(&v))?);
            }
            lookup_sets.push(set);
        }
        let mut text_ids: Option<HashSet<u64>> = None;
        if let Some(t) = &self.text_search {
            text_ids = Some(self.text_search_ids(view, settings, t)?);
        }
        let candidates: Option<Vec<u64>> = if let Some(pks) = &self.rpsl_pks {
            let mut ids = Vec::new();
            for pk in pks {
                ids.extend(view.ids_by_rpsl_pk(pk)?);
            }
            Some(ids)
        } else if let Some(set) = lookup_sets.first() {
            Some(set.iter().copied().collect())
        } else if let Some(t) = &text_ids {
            Some(t.iter().copied().collect())
        } else if let Some(asns) = &self.asns_first {
            let mut ids = Vec::new();
            for a in asns {
                if let Ok(a) = u32::try_from(*a) {
                    ids.extend(view.ids_by_asn_first(a)?);
                }
            }
            Some(ids)
        } else if let Some((f, ip)) = self.ip.first() {
            Some(self.ip_candidates(view, *f, ip)?)
        } else {
            None
        };

        let passes = |id: u64, o: &RpslObjectRef<'_>| -> bool {
            if let Some(pks) = &self.rpsl_pks
                && !pks.iter().any(|p| p == o.rpsl_pk)
            {
                return false;
            }
            if !self
                .classes
                .iter()
                .all(|l| l.iter().any(|c| c == o.object_class))
            {
                return false;
            }
            if let Some(asns) = &self.asns_first
                && !o.asn_first.is_some_and(|a| asns.contains(&i128::from(a)))
            {
                return false;
            }
            if !rpki_ok(&self.rpki, o) {
                return false;
            }
            if let Some(l) = &self.scope
                && !l.contains(&o.scopefilter_status)
            {
                return false;
            }
            if let Some(l) = &self.routepref
                && !l.contains(&o.route_preference_status)
            {
                return false;
            }
            if let Some(s) = &self.sources
                && !s.iter().any(|x| x == o.source)
            {
                return false;
            }
            if !lookup_sets.iter().all(|s| s.contains(&id)) {
                return false;
            }
            if let Some(t) = &text_ids
                && !t.contains(&id)
            {
                return false;
            }
            for (f, ip) in &self.ip {
                if *f == IpFilter::LessSpecificOneLevel {
                    continue;
                }
                if !ip_matches(*f, ip, o, prefix_ok) {
                    return false;
                }
            }
            true
        };

        let mut out: Vec<Found<'t>> = Vec::new();
        match candidates {
            Some(mut ids) => {
                ids.sort_unstable();
                ids.dedup();
                for id in ids {
                    if let Some(o) = view.object_by_id(id)?
                        && passes(id, &o)
                    {
                        out.push((id, o));
                    }
                }
            }
            None => {
                // A scan, narrowed by source and class where given.
                let sources: Vec<Option<String>> = match &self.sources {
                    Some(s) => s.iter().cloned().map(Some).collect(),
                    None => vec![None],
                };
                let classes: Vec<Option<String>> = match self.classes.first() {
                    Some(c) => c.iter().cloned().map(Some).collect(),
                    None => vec![None],
                };
                let mut seen = HashSet::new();
                for s in &sources {
                    for c in &classes {
                        let class = if s.is_some() { c.as_deref() } else { None };
                        for item in view.objects(s.as_deref(), class)? {
                            let (id, o) = item?;
                            if seen.insert(id) && passes(id, &o) {
                                out.push((id, o));
                            }
                        }
                        if s.is_none() {
                            break;
                        }
                    }
                }
                out.sort_by_key(|(id, _)| *id);
            }
        }

        // ip_less_specific_one_level: only the smallest matches, among the
        // rows every other filter admits.
        if let Some((_, ip)) = self
            .ip
            .iter()
            .find(|(f, _)| *f == IpFilter::LessSpecificOneLevel)
        {
            let q = IpBounds::of(ip);
            out.retain(|(_, o)| q.less_or_exact(o) && !q.exact(o));
            let size = |o: &RpslObjectRef<'_>| match (o.ip_first, o.ip_last) {
                (Some(a), Some(b)) => Some(addr_u128(&b).wrapping_sub(addr_u128(&a))),
                _ => None,
            };
            if let Some(min) = out.iter().filter_map(|(_, o)| size(o)).min() {
                out.retain(|(_, o)| size(o) == Some(min));
            } else {
                out.clear();
            }
        }
        if let Some(limit) = self.limit {
            if limit < 0 {
                return Err(QueryError::Internal(
                    "LIMIT must not be negative".to_owned(),
                ));
            }
            out.truncate(limit as usize);
        }
        Ok(out)
    }

    fn ip_candidates(&self, view: &ReadView<'_>, f: IpFilter, ip: &Ip) -> QResult<Vec<u64>> {
        let q = IpBounds::of(ip);
        let space = q.space();
        let ids = match f {
            IpFilter::Exact => view.range_exact(space, q.net, q.bcast)?,
            IpFilter::MoreSpecific => view.range_more_specific(space, q.net, q.bcast)?,
            IpFilter::LessSpecific | IpFilter::LessSpecificOneLevel => {
                if q.consistent() {
                    view.range_less_specific(space, q.net, q.bcast)?
                } else {
                    view.range_first_at_most(space, q.net)?
                }
            }
            IpFilter::Any => {
                let mut v = if q.consistent() {
                    view.range_less_specific(space, q.net, q.bcast)?
                } else {
                    view.range_first_at_most(space, q.net)?
                };
                v.extend(view.range_more_specific(space, q.net, q.bcast)?);
                v
            }
        };
        Ok(ids.into_iter().map(|(id, _, _)| id).collect())
    }

    /// `text_search(value)`: the matching ids.
    fn text_search_ids(
        &self,
        view: &ReadView<'_>,
        settings: &QuerySettings,
        value: &str,
    ) -> QResult<HashSet<u64>> {
        let mut out = HashSet::new();
        if let Ok((_, asn)) = rpsl::parse_as_number(value, false, true, settings.asdot_queries) {
            for (id, _, _) in
                view.range_less_specific(store::Space::Asn, u128::from(asn), u128::from(asn))?
            {
                if let Some(o) = view.object_by_id(id)?
                    && matches!(o.object_class, "as-block" | "as-set" | "aut-num")
                {
                    out.insert(id);
                }
            }
            return Ok(out);
        }
        if let Some(ip) = crate::resolver::ipy(value) {
            let prefix_ok = self.prefix_permitted(settings);
            for id in self.ip_candidates(view, IpFilter::LessSpecific, &ip)? {
                if let Some(o) = view.object_by_id(id)?
                    && ip_matches(IpFilter::LessSpecific, &ip, &o, prefix_ok)
                {
                    out.insert(id);
                }
            }
            return Ok(out);
        }
        let upper = rpsl::python::upper(value);
        out.extend(view.ids_by_rpsl_pk(&upper)?);
        let pattern = like_pattern(&format!("%{value}%"));
        let sources: Vec<String> = view
            .database_statuses()?
            .into_iter()
            .map(|s| s.source)
            .collect();
        for class in ["person", "role"] {
            for source in &sources {
                for item in view.objects(Some(source), Some(class))? {
                    let (id, o) = item?;
                    if parsed_field(o.parsed_data, class)
                        .first()
                        .is_some_and(|v| ilike(&pattern, v))
                    {
                        out.insert(id);
                    }
                }
            }
        }
        Ok(out)
    }
}

/// One IP filter's predicate on a row.
fn ip_matches(f: IpFilter, ip: &Ip, o: &RpslObjectRef<'_>, prefix_ok: bool) -> bool {
    let q = IpBounds::of(ip);
    match f {
        IpFilter::Exact => q.exact(o),
        IpFilter::LessSpecific => {
            if prefix_ok {
                prefix_relation(o, &q, false)
            } else {
                q.less_or_exact(o)
            }
        }
        IpFilter::MoreSpecific => {
            if prefix_ok {
                prefix_relation(o, &q, true)
            } else {
                q.more_specific(o)
            }
        }
        IpFilter::LessSpecificOneLevel => q.less_or_exact(o) && !q.exact(o),
        IpFilter::Any => {
            if prefix_ok {
                prefix_relation(o, &q, false) || prefix_relation(o, &q, true)
            } else {
                // (first <= net AND last >= bcast) OR (first >= net AND
                // first <= bcast AND last <= bcast AND last >= net), in
                // the query's IP version.
                let Some((f, l)) = q.row(o) else {
                    return false;
                };
                let (n, b) = (q.q_net(), q.q_bcast());
                (f <= n && l >= b) || (f >= n && f <= b && l <= b && l >= n)
            }
        }
    }
}
