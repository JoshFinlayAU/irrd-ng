//! `irrd/routepref/routepref.py`: route object preference.
//!
//! Every route and route6 object from a source with
//! `route_object_preference` is suppressed when an overlapping route
//! (covering, covered or the same prefix) from a source with a higher
//! preference exists, and visible otherwise. Objects from sources without a
//! preference are always made visible.
//!
//! v4 builds a py-radix tree and searches covered and covering nodes for
//! every node. Here the distinct prefixes are sorted, which lays them out
//! as a pre-order walk of the containment tree, and one pass with a stack
//! gives every prefix the highest preference among its ancestors and among
//! its descendants. The answer is the same, in O(n log n).

use std::collections::{HashMap, HashSet};

use store::{
    IpPrefix, ReadView, Result, RoutePreferenceStatus, Space, StatusChange, Uuid, WriteTx,
};

use crate::messages;

/// v4's logger.
pub const LOG_TARGET: &str = "irrd.routepref.routepref";

/// `MAX_FILTER_PREFIX_LEN`: more changed prefixes than this and the whole
/// table is evaluated.
pub const MAX_FILTER_PREFIX_LEN: usize = 5000;

/// One route as the validator sees it (v4's `prefix, source, pk,
/// route_preference_status` columns).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRow {
    /// `pk`
    pub pk: Uuid,
    /// `prefix`
    pub prefix: IpPrefix,
    /// `source`
    pub source: String,
    /// `route_preference_status`
    pub status: RoutePreferenceStatus,
}

/// `RoutePreferenceValidator`.
#[derive(Debug, Default)]
pub struct RoutePreferenceValidator {
    source_preferences: HashMap<String, i64>,
    max_preference: Option<i64>,
    /// (prefix, pk, preference, current status), one per pk.
    routes: Vec<(IpPrefix, Uuid, i64, RoutePreferenceStatus)>,
    /// `excluded_currently_suppressed`, with v4's repeats.
    pub excluded_currently_suppressed: Vec<Uuid>,
}

impl RoutePreferenceValidator {
    /// `RoutePreferenceValidator(existing_route_objects)`, with the
    /// preferences of the sources that set one.
    pub fn new(
        source_preferences: HashMap<String, i64>,
        rows: impl IntoIterator<Item = RouteRow>,
    ) -> Self {
        let max_preference = source_preferences.values().copied().max();
        let mut v = RoutePreferenceValidator {
            source_preferences,
            max_preference,
            ..Default::default()
        };
        let mut seen: HashSet<Uuid> = HashSet::new();
        for row in rows {
            match v.source_preferences.get(&row.source) {
                None => {
                    if row.status != RoutePreferenceStatus::Visible {
                        v.excluded_currently_suppressed.push(row.pk);
                    }
                }
                Some(&p) => {
                    // rnode.data[pk] = ...: one entry per pk and prefix.
                    if seen.insert(row.pk) {
                        v.routes.push((row.prefix, row.pk, p, row.status));
                    }
                }
            }
        }
        v
    }

    /// `validate_known_routes()`: (to become visible, to be suppressed).
    pub fn validate_known_routes(&self) -> (Vec<Uuid>, Vec<Uuid>) {
        if self.source_preferences.is_empty() {
            return (Vec::new(), Vec::new());
        }
        // Highest preference per distinct prefix.
        let mut node_max: HashMap<IpPrefix, i64> = HashMap::new();
        for (prefix, _, p, _) in &self.routes {
            let e = node_max.entry(*prefix).or_insert(*p);
            if *p > *e {
                *e = *p;
            }
        }
        let mut nodes: Vec<(IpPrefix, i64)> = node_max.into_iter().collect();
        nodes.sort_by_key(|(p, _)| (p.version(), p.first(), p.len));
        let n = nodes.len();
        let mut anc = vec![i64::MIN; n];
        let mut sub: Vec<i64> = nodes.iter().map(|(_, m)| *m).collect();
        let mut stack: Vec<usize> = Vec::new();
        let contains = |a: &IpPrefix, b: &IpPrefix| {
            a.version() == b.version() && a.first() <= b.first() && b.last() <= a.last()
        };
        for i in 0..n {
            while let Some(&top) = stack.last() {
                if contains(&nodes[top].0, &nodes[i].0) {
                    break;
                }
                stack.pop();
                if let Some(&parent) = stack.last() {
                    sub[parent] = sub[parent].max(sub[top]);
                }
            }
            anc[i] = match stack.last() {
                Some(&top) => anc[top].max(nodes[i].1),
                None => nodes[i].1,
            };
            stack.push(i);
        }
        while let Some(top) = stack.pop() {
            if let Some(&parent) = stack.last() {
                sub[parent] = sub[parent].max(sub[top]);
            }
        }
        let overlap: HashMap<IpPrefix, i64> = nodes
            .iter()
            .enumerate()
            .map(|(i, (p, _))| (*p, anc[i].max(sub[i])))
            .collect();

        let mut to_be_visible = Vec::new();
        let mut to_be_suppressed = Vec::new();
        let mut order: Vec<&(IpPrefix, Uuid, i64, RoutePreferenceStatus)> =
            self.routes.iter().collect();
        order.sort_by_key(|(p, _, _, _)| (p.version(), p.first(), p.len));
        for (prefix, pk, pref, current) in order {
            let new = if Some(*pref) == self.max_preference
                || overlap.get(prefix).is_none_or(|m| *m <= *pref)
            {
                RoutePreferenceStatus::Visible
            } else {
                RoutePreferenceStatus::Suppressed
            };
            if new != *current {
                match new {
                    RoutePreferenceStatus::Suppressed => to_be_suppressed.push(*pk),
                    RoutePreferenceStatus::Visible => to_be_visible.push(*pk),
                }
            }
        }
        (to_be_visible, to_be_suppressed)
    }
}

fn row_of(o: &store::RpslObjectRef<'_>) -> Option<RouteRow> {
    Some(RouteRow {
        pk: o.pk,
        prefix: o.prefix?,
        source: o.source.to_owned(),
        status: o.route_preference_status,
    })
}

/// Every route and route6 object.
fn all_rows(view: &ReadView<'_>) -> Result<Vec<RouteRow>> {
    let mut out = Vec::new();
    for source in view.object_sources()? {
        for class in ["route", "route6"] {
            for item in view.objects(Some(&source), Some(class))? {
                let (_, o) = item?;
                if let Some(r) = row_of(&o) {
                    out.push(r);
                }
            }
        }
    }
    Ok(out)
}

/// Route and route6 objects whose prefix contains `filter` or lies
/// strictly inside it: v4's `ip_any()` on the `prefix` column
/// (`prefix >>= filter OR prefix << filter`).
fn rows_overlapping(view: &ReadView<'_>, filter: &IpPrefix, out: &mut Vec<RouteRow>) -> Result<()> {
    let space = Space::of(&filter.addr);
    let (first, last) = (filter.first(), filter.last());
    let mut ids: Vec<u64> = view
        .range_less_specific(space, first, last)?
        .into_iter()
        .chain(view.range_more_specific(space, first, last)?)
        .map(|(id, _, _)| id)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    for id in ids {
        let Some(o) = view.object_by_id(id)? else {
            continue;
        };
        if !matches!(o.object_class, "route" | "route6") {
            continue;
        }
        let Some(p) = o.prefix else { continue };
        if p.version() != filter.version() {
            continue;
        }
        let covers = p.first() <= first && last <= p.last();
        let inside = first <= p.first() && p.last() <= last && p != *filter;
        if covers || inside {
            out.extend(row_of(&o));
        }
    }
    Ok(())
}

/// `update_route_preference_status(database_handler, filter_prefixes)`:
/// work out and write the new statuses, with journal entries, and log the
/// counts. Does nothing unless some source sets a (non-zero) preference.
pub fn update_route_preference_status(
    tx: &mut WriteTx<'_, '_>,
    filter_prefixes: Option<&[IpPrefix]>,
) -> Result<()> {
    if !tx.settings().route_preference_enabled() {
        return Ok(());
    }
    let filter_prefixes =
        filter_prefixes.filter(|f| f.len() <= MAX_FILTER_PREFIX_LEN && !f.is_empty());
    let preferences: HashMap<String, i64> = tx
        .settings()
        .sources
        .iter()
        .filter_map(|(name, s)| s.route_object_preference.map(|p| (name.clone(), p)))
        .collect();
    let (visible, suppressed, counts) = {
        let view = tx.read()?;
        let rows = match filter_prefixes {
            None => all_rows(&view)?,
            Some(prefixes) => {
                let mut rows = Vec::new();
                for p in prefixes {
                    rows_overlapping(&view, p, &mut rows)?;
                }
                rows
            }
        };
        let validator = RoutePreferenceValidator::new(preferences, rows);
        let (to_be_visible, to_be_suppressed) = validator.validate_known_routes();
        let counts = (
            to_be_visible.len(),
            to_be_suppressed.len(),
            validator.excluded_currently_suppressed.len(),
        );
        let mut become_visible = to_be_visible;
        become_visible.extend(validator.excluded_currently_suppressed.iter().copied());
        (
            enrich(&view, &become_visible)?,
            enrich(&view, &to_be_suppressed)?,
            counts,
        )
    };
    tx.update_route_preference_status(&visible, &suppressed)?;
    let common = messages::routepref_common(counts.0, counts.1, counts.2);
    match filter_prefixes {
        None => tracing::info!(target: LOG_TARGET, "{}", messages::routepref_all(&common)),
        Some(f) => {
            tracing::info!(target: LOG_TARGET, "{}", messages::routepref_subset(f.len(), &common))
        }
    }
    Ok(())
}

/// `enrich_pks()`: the columns the journal needs, once per pk (an `IN`
/// list).
fn enrich(view: &ReadView<'_>, pks: &[Uuid]) -> Result<Vec<StatusChange<()>>> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(pks.len());
    for pk in pks {
        if !seen.insert(*pk) {
            continue;
        }
        if let Some(o) = view.object_by_pk(pk)? {
            out.push(StatusChange {
                pk: o.pk,
                rpsl_pk: o.rpsl_pk.to_owned(),
                source: o.source.to_owned(),
                object_class: o.object_class.to_owned(),
                object_text: o.object_text.to_owned(),
                prefix: o.prefix,
                old_status: (),
                rpki_status: o.rpki_status,
                scopefilter_status: o.scopefilter_status,
                route_preference_status: o.route_preference_status,
            });
        }
    }
    Ok(out)
}

/// The store's pre-commit hook: re-evaluate around the prefixes of route
/// objects changed in the transaction, as v4's
/// `SessionChangedObjectsTracker.pre_commit()` does.
pub fn route_preference_hook(tx: &mut WriteTx<'_, '_>, prefixes: &[IpPrefix]) -> Result<()> {
    update_route_preference_status(tx, Some(prefixes))
}

#[cfg(test)]
mod tests {
    //! v4's `irrd/routepref/tests/test_routepref.py`.

    use super::*;

    fn row(prefix: &str, source: &str, n: u128, status: RoutePreferenceStatus) -> RouteRow {
        RouteRow {
            pk: Uuid::from_u128(n),
            prefix: IpPrefix::parse(prefix).expect("prefix"),
            source: source.into(),
            status,
        }
    }

    fn ids(v: &[Uuid]) -> Vec<u128> {
        let mut x: Vec<u128> = v.iter().map(|u| u.as_u128()).collect();
        x.sort_unstable();
        x
    }

    // test_route_preference_validator: routes A..I are 1..9.
    #[test]
    fn validator() {
        use RoutePreferenceStatus::{Suppressed as S, Visible as V};
        let rows = || {
            vec![
                row("192.0.0.0/23", "SRC-HIGH-A", 1, S),
                row("192.0.0.0/24", "SRC-HIGH-B", 2, S),
                row("192.0.0.0/23", "SRC-LOWEST", 3, V),
                row("192.0.0.0/22", "SRC-LOW", 4, V),
                row("192.0.1.0/24", "SRC-LOW", 5, V),
                row("192.0.3.0/24", "SRC-LOWEST", 6, V),
                row("192.0.0.0/24", "SRC-NOPREF", 7, S),
                row("192.0.0.0/32", "SRC-NOPREF", 8, V),
                row("198.51.100.0/24", "SRC-LOWEST", 9, S),
            ]
        };
        let prefs: HashMap<String, i64> = [
            ("SRC-HIGH-A".to_owned(), 900),
            ("SRC-HIGH-B".to_owned(), 900),
            ("SRC-LOWEST".to_owned(), 100),
            ("SRC-LOW".to_owned(), 200),
        ]
        .into();
        let v = RoutePreferenceValidator::new(prefs, rows());
        let (visible, suppressed) = v.validate_known_routes();
        assert_eq!(ids(&v.excluded_currently_suppressed), vec![7]);
        assert_eq!(ids(&visible), vec![1, 2, 9]);
        assert_eq!(ids(&suppressed), vec![3, 4, 5, 6]);

        let v = RoutePreferenceValidator::new(HashMap::new(), rows());
        let (visible, suppressed) = v.validate_known_routes();
        assert_eq!(ids(&v.excluded_currently_suppressed), vec![1, 2, 7, 9]);
        assert!(visible.is_empty() && suppressed.is_empty());
    }

    #[test]
    fn no_preferences_no_changes() {
        let v = RoutePreferenceValidator::new(
            HashMap::new(),
            vec![row(
                "192.0.2.0/24",
                "X",
                1,
                RoutePreferenceStatus::Suppressed,
            )],
        );
        assert_eq!(v.validate_known_routes(), (vec![], vec![]));
        assert_eq!(v.excluded_currently_suppressed.len(), 1);
    }

    #[test]
    fn equal_preferences_do_not_suppress() {
        let prefs: HashMap<String, i64> = [
            ("A".to_owned(), 100),
            ("B".to_owned(), 100),
            ("C".to_owned(), 200),
        ]
        .into();
        let v = RoutePreferenceValidator::new(
            prefs,
            vec![
                row("10.0.0.0/8", "A", 1, RoutePreferenceStatus::Suppressed),
                row("10.1.0.0/16", "B", 2, RoutePreferenceStatus::Visible),
                row("11.0.0.0/8", "C", 3, RoutePreferenceStatus::Visible),
                // Siblings do not overlap.
                row("10.2.0.0/16", "A", 4, RoutePreferenceStatus::Visible),
                row("10.3.0.0/16", "C", 5, RoutePreferenceStatus::Visible),
            ],
        );
        let (vis, sup) = v.validate_known_routes();
        // The A /8 covers the C /16, so it is suppressed; nothing else.
        assert!(vis.is_empty());
        assert!(sup.is_empty());
        let v2 = RoutePreferenceValidator::new(
            [("A".to_owned(), 100), ("C".to_owned(), 200)].into(),
            vec![
                row("10.0.0.0/8", "A", 1, RoutePreferenceStatus::Visible),
                row("10.3.0.0/16", "C", 5, RoutePreferenceStatus::Visible),
                row("10.2.0.0/16", "A", 4, RoutePreferenceStatus::Visible),
            ],
        );
        let (vis, sup) = v2.validate_known_routes();
        assert!(vis.is_empty());
        assert_eq!(sup, vec![Uuid::from_u128(1)]);
    }
}
