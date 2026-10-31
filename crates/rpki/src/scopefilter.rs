//! `irrd/scopefilter/validators.py` `ScopeFilterValidator`.

use std::collections::{HashMap, HashSet};

use store::{IpPrefix, ScopeFilterStatus};

/// The scope filter configuration (`scopefilter.prefixes`,
/// `scopefilter.asns`) and per-source `scopefilter_excluded`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeFilterConfig {
    /// `scopefilter.prefixes`, already validated by the config checks.
    pub prefixes: Vec<IpPrefix>,
    /// Single ASNs from `scopefilter.asns`.
    pub asns: HashSet<u64>,
    /// `start-end` ranges from `scopefilter.asns`.
    pub asn_ranges: Vec<(u64, u64)>,
    /// `sources.X.scopefilter_excluded`, per source.
    pub excluded_sources: HashMap<String, bool>,
}

/// v4's scope filter validator.
#[derive(Debug, Clone, Default)]
pub struct ScopeFilterValidator {
    config: ScopeFilterConfig,
}

impl ScopeFilterValidator {
    /// A validator for a configuration.
    pub fn new(config: ScopeFilterConfig) -> Self {
        ScopeFilterValidator { config }
    }

    /// `validate(source, prefix, asn)`.
    pub fn validate(
        &self,
        source: &str,
        prefix: Option<&IpPrefix>,
        asn: Option<u32>,
    ) -> ScopeFilterStatus {
        if self
            .config
            .excluded_sources
            .get(source)
            .copied()
            .unwrap_or(false)
        {
            return ScopeFilterStatus::InScope;
        }
        if let Some(p) = prefix {
            for f in &self.config.prefixes {
                if p.version() == f.version() && overlaps(f, p) {
                    return ScopeFilterStatus::OutScopePrefix;
                }
            }
        }
        if let Some(asn) = asn {
            let asn = u64::from(asn);
            if self.config.asns.contains(&asn) {
                return ScopeFilterStatus::OutScopeAs;
            }
            for (start, end) in &self.config.asn_ranges {
                if *start <= asn && asn <= *end {
                    return ScopeFilterStatus::OutScopeAs;
                }
            }
        }
        ScopeFilterStatus::InScope
    }

    /// `validate_rpsl_object(obj)`'s status: only route, route6 and aut-num
    /// objects are filtered, on their prefix, then their first ASN.
    pub fn validate_rpsl_object(
        &self,
        source: &str,
        object_class: &str,
        prefix: Option<&IpPrefix>,
        asn_first: Option<u32>,
    ) -> ScopeFilterStatus {
        if !matches!(object_class, "route" | "route6" | "aut-num") {
            return ScopeFilterStatus::InScope;
        }
        if let Some(p) = prefix {
            let s = self.validate(source, Some(p), None);
            if s != ScopeFilterStatus::InScope {
                return s;
            }
        }
        if let Some(a) = asn_first {
            let s = self.validate(source, None, Some(a));
            if s != ScopeFilterStatus::InScope {
                return s;
            }
        }
        ScopeFilterStatus::InScope
    }
}

/// `IP.overlaps(item)` is non-zero.
fn overlaps(a: &IpPrefix, b: &IpPrefix) -> bool {
    (b.first() >= a.first() && b.first() <= a.last())
        || (a.first() >= b.first() && a.first() <= b.last())
}

#[cfg(test)]
mod tests {
    use super::*;

    // v4's test_scopefilter.py TestScopeFilterValidator.test_validate.
    #[test]
    fn validate() {
        let p = |s: &str| IpPrefix::parse(s).expect("prefix");
        let mut c = ScopeFilterConfig {
            prefixes: vec![p("10.0.0.0/8"), p("192.168.0.0/24")],
            asns: [23456].into_iter().collect(),
            asn_ranges: vec![(10, 20)],
            ..Default::default()
        };
        c.excluded_sources.insert("TEST-EXCLUDED".into(), true);
        let v = ScopeFilterValidator::new(c);
        assert_eq!(
            v.validate("TEST", Some(&p("192.0.2.0/24")), None),
            ScopeFilterStatus::InScope
        );
        assert_eq!(
            v.validate("TEST", Some(&p("192.168.0.0/24")), None),
            ScopeFilterStatus::OutScopePrefix
        );
        assert_eq!(
            v.validate("TEST", Some(&p("10.2.1.0/24")), None),
            ScopeFilterStatus::OutScopePrefix
        );
        assert_eq!(
            v.validate("TEST", Some(&p("192.0.0.0/8")), None),
            ScopeFilterStatus::OutScopePrefix
        );
        assert_eq!(
            v.validate("TEST", None, Some(9)),
            ScopeFilterStatus::InScope
        );
        assert_eq!(
            v.validate("TEST", None, Some(21)),
            ScopeFilterStatus::InScope
        );
        assert_eq!(
            v.validate("TEST", None, Some(20)),
            ScopeFilterStatus::OutScopeAs
        );
        assert_eq!(
            v.validate("TEST", None, Some(10)),
            ScopeFilterStatus::OutScopeAs
        );
        assert_eq!(
            v.validate("TEST", None, Some(15)),
            ScopeFilterStatus::OutScopeAs
        );
        assert_eq!(
            v.validate("TEST", None, Some(23456)),
            ScopeFilterStatus::OutScopeAs
        );
        assert_eq!(
            v.validate("TEST-EXCLUDED", Some(&p("192.0.0.0/8")), None),
            ScopeFilterStatus::InScope
        );
        assert_eq!(
            v.validate("TEST-EXCLUDED", None, Some(20)),
            ScopeFilterStatus::InScope
        );

        let none = ScopeFilterValidator::new(ScopeFilterConfig::default());
        assert_eq!(
            none.validate("TEST", Some(&p("192.168.0.0/24")), None),
            ScopeFilterStatus::InScope
        );
        assert_eq!(
            none.validate("TEST", None, Some(20)),
            ScopeFilterStatus::InScope
        );
    }
}
