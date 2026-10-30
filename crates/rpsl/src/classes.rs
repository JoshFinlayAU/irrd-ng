//! The 19 RPSL object classes: a port of the field tables in
//! `irrd/rpsl/rpsl_objects.py`, in v4's attribute order.

use crate::fields::{FieldDef, FieldKind};

/// One RPSL object class.
#[derive(Debug)]
pub struct ClassDef {
    /// Object class name, e.g. `route6`.
    pub name: &'static str,
    /// Attributes in v4's order. The first is the class attribute.
    pub fields: &'static [FieldDef],
    /// Attributes dropped while parsing (`discarded_fields`).
    pub discarded_fields: &'static [&'static str],
    /// `is_route`: route and route6.
    pub is_route: bool,
    /// Subclass of v4's `RPSLSet` (has `clean_for_create` set name checks).
    pub is_set: bool,
}

impl ClassDef {
    /// Look up a field by attribute name.
    pub fn field(&self, name: &str) -> Option<&'static FieldDef> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// `pk_fields`: names of the primary key attributes, in order.
    pub fn pk_fields(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.fields.iter().filter(|f| f.primary_key).map(|f| f.name)
    }

    /// `lookup_fields`: names of the look-up key attributes, in order.
    pub fn lookup_fields(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.fields.iter().filter(|f| f.lookup_key).map(|f| f.name)
    }

    /// `generate_template()`: v4's `-t` output for this class.
    pub fn generate_template(&self) -> String {
        crate::template::generate(self)
    }
}

const fn f(name: &'static str, kind: FieldKind) -> FieldDef {
    FieldDef {
        name,
        kind,
        optional: false,
        multiple: false,
        primary_key: false,
        lookup_key: false,
    }
}

impl FieldDef {
    const fn opt(mut self) -> Self {
        self.optional = true;
        self
    }
    const fn mult(mut self) -> Self {
        self.multiple = true;
        self
    }
    const fn pk(mut self) -> Self {
        self.primary_key = true;
        self
    }
    const fn lookup(mut self) -> Self {
        self.lookup_key = true;
        self
    }
    /// primary_key=True, lookup_key=True
    const fn pkl(self) -> Self {
        self.pk().lookup()
    }
}

const TEXT: FieldKind = FieldKind::Text;
const EMAIL: FieldKind = FieldKind::Email;
const CHANGED: FieldKind = FieldKind::Changed;
const NAME: FieldKind = FieldKind::GenericName {
    allowed_prefixes: &[],
    non_strict_allow_any: false,
};
const NIC_HDL: FieldKind = FieldKind::GenericName {
    allowed_prefixes: &[],
    non_strict_allow_any: true,
};
const CONTACT: FieldKind = FieldKind::Reference {
    referring: &["role", "person"],
    strong: true,
};
const MNT_BY: FieldKind = FieldKind::ReferenceList {
    referring: &["mntner"],
    strong: true,
    allow_kw_any: false,
};
const MBRS_BY_REF: FieldKind = FieldKind::ReferenceList {
    referring: &["mntner"],
    strong: false,
    allow_kw_any: true,
};
const fn weak_list(referring: &'static [&'static str]) -> FieldKind {
    FieldKind::ReferenceList {
        referring,
        strong: false,
        allow_kw_any: false,
    }
}

// Shorthands for the attributes nearly every class ends with.
const DESCR: FieldDef = f("descr", TEXT).mult().opt();
const REMARKS: FieldDef = f("remarks", TEXT).opt().mult();
const NOTIFY: FieldDef = f("notify", EMAIL).opt().mult();
const CHANGED_F: FieldDef = f("changed", CHANGED).opt().mult();
const SOURCE: FieldDef = f("source", NAME);
const ADMIN_C: FieldDef = f("admin-c", CONTACT).lookup().mult();
const TECH_C: FieldDef = f("tech-c", CONTACT).lookup().mult();
const ADMIN_C_OPT: FieldDef = f("admin-c", CONTACT).lookup().opt().mult();
const TECH_C_OPT: FieldDef = f("tech-c", CONTACT).lookup().opt().mult();
const MNT_BY_F: FieldDef = f("mnt-by", MNT_BY).lookup().mult();
const MNT_BY_OPT: FieldDef = f("mnt-by", MNT_BY).lookup().opt().mult();

const fn class(name: &'static str, fields: &'static [FieldDef]) -> ClassDef {
    ClassDef {
        name,
        fields,
        discarded_fields: &[],
        is_route: false,
        is_set: false,
    }
}

const fn set_class(name: &'static str, fields: &'static [FieldDef]) -> ClassDef {
    ClassDef {
        name,
        fields,
        discarded_fields: &[],
        is_route: false,
        is_set: true,
    }
}

const fn route_class(name: &'static str, fields: &'static [FieldDef]) -> ClassDef {
    ClassDef {
        name,
        fields,
        discarded_fields: &["rpki-ov-state"],
        is_route: true,
        is_set: false,
    }
}

static AS_BLOCK: ClassDef = class(
    "as-block",
    &[
        f("as-block", FieldKind::AsBlock).pkl(),
        DESCR,
        ADMIN_C,
        TECH_C,
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static AS_SET: ClassDef = set_class(
    "as-set",
    &[
        f("as-set", FieldKind::SetName { prefix: "AS-" }).pkl(),
        DESCR,
        f("members", weak_list(&["aut-num", "as-set"]))
            .lookup()
            .opt()
            .mult(),
        f("mbrs-by-ref", MBRS_BY_REF).lookup().opt().mult(),
        ADMIN_C_OPT,
        TECH_C_OPT,
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static AUT_NUM: ClassDef = class(
    "aut-num",
    &[
        f("aut-num", FieldKind::AsNumber).pkl(),
        f(
            "as-name",
            FieldKind::GenericName {
                allowed_prefixes: &["AS-"],
                non_strict_allow_any: false,
            },
        ),
        DESCR,
        f("member-of", weak_list(&["as-set"])).lookup().opt().mult(),
        f("import", TEXT).opt().mult(),
        f("mp-import", TEXT).opt().mult(),
        f("import-via", TEXT).opt().mult(),
        f("export", TEXT).opt().mult(),
        f("mp-export", TEXT).opt().mult(),
        f("export-via", TEXT).opt().mult(),
        f("default", TEXT).opt().mult(),
        f("mp-default", TEXT).opt().mult(),
        ADMIN_C,
        TECH_C,
        REMARKS,
        NOTIFY,
        MNT_BY_OPT,
        CHANGED_F,
        SOURCE,
    ],
);

static DOMAIN: ClassDef = class(
    "domain",
    &[
        f("domain", TEXT).pkl(),
        DESCR,
        ADMIN_C,
        TECH_C,
        f("zone-c", CONTACT).lookup().mult(),
        f("nserver", TEXT).opt().mult(),
        f("sub-dom", TEXT).opt().mult(),
        f("dom-net", TEXT).opt().mult(),
        f("refer", TEXT).opt(),
        REMARKS,
        NOTIFY,
        MNT_BY_OPT,
        CHANGED_F,
        SOURCE,
    ],
);

static FILTER_SET: ClassDef = set_class(
    "filter-set",
    &[
        f("filter-set", FieldKind::SetName { prefix: "FLTR-" }).pkl(),
        DESCR,
        f("filter", TEXT),
        f("mp-filter", TEXT).opt(),
        ADMIN_C_OPT,
        TECH_C_OPT,
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static INET_RTR: ClassDef = class(
    "inet-rtr",
    &[
        f("inet-rtr", FieldKind::DnsName).pkl(),
        DESCR,
        f("alias", FieldKind::DnsName).opt().mult(),
        f("local-as", FieldKind::AsNumber),
        f("ifaddr", TEXT).opt().mult(),
        f("interface", TEXT).opt().mult(),
        f("peer", TEXT).opt().mult(),
        f("mp-peer", TEXT).opt().mult(),
        f("member-of", weak_list(&["rtr-set"]))
            .lookup()
            .opt()
            .mult(),
        f("rs-in", TEXT).opt(),
        f("rs-out", TEXT).opt(),
        ADMIN_C_OPT,
        TECH_C_OPT,
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static INET6NUM: ClassDef = class(
    "inet6num",
    &[
        f("inet6num", FieldKind::Ipv6Prefix).pkl(),
        f("netname", TEXT),
        DESCR,
        f("country", TEXT).mult(),
        ADMIN_C,
        TECH_C,
        f("rev-srv", TEXT).opt().mult(),
        f("status", TEXT),
        f("geofeed", FieldKind::Url).opt(),
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static INETNUM: ClassDef = class(
    "inetnum",
    &[
        f("inetnum", FieldKind::Ipv4AddressRange).pkl(),
        f("netname", TEXT),
        DESCR,
        f("country", TEXT).mult(),
        ADMIN_C,
        TECH_C,
        f("rev-srv", TEXT).opt().mult(),
        f("status", TEXT),
        f("geofeed", FieldKind::Url).opt(),
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static IRT: ClassDef = class(
    "irt",
    &[
        f("irt", NAME).pkl(),
        f("address", TEXT).mult(),
        f("phone", TEXT).opt().mult(),
        f("fax-no", TEXT).opt().mult(),
        f("e-mail", EMAIL).mult(),
        f("abuse-mailbox", EMAIL).mult(),
        ADMIN_C_OPT,
        TECH_C_OPT,
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static KEY_CERT: ClassDef = class(
    "key-cert",
    &[
        f("key-cert", NAME).pkl(),
        f("method", TEXT).opt(),
        f("owner", TEXT).opt().mult(),
        f("fingerpr", TEXT).opt(),
        f("certif", TEXT).mult(),
        REMARKS,
        ADMIN_C_OPT,
        TECH_C_OPT,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static MNTNER: ClassDef = class(
    "mntner",
    &[
        f("mntner", NAME).pkl(),
        DESCR,
        ADMIN_C,
        TECH_C_OPT,
        f("upd-to", EMAIL).mult(),
        f("mnt-nfy", EMAIL).opt().mult(),
        f("auth", FieldKind::Auth).mult(),
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static ORGANISATION: ClassDef = class(
    "organisation",
    &[
        f("organisation", NAME).pkl(),
        f("org-name", TEXT),
        f("country", TEXT).mult(),
        f("address", TEXT).mult(),
        f("phone", TEXT).opt().mult(),
        f("fax-no", TEXT).opt().mult(),
        f("e-mail", EMAIL).mult(),
        ADMIN_C_OPT,
        TECH_C_OPT,
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static PEERING_SET: ClassDef = set_class(
    "peering-set",
    &[
        f("peering-set", FieldKind::SetName { prefix: "PRNG-" }).pkl(),
        DESCR,
        f("peering", TEXT).opt().mult(),
        f("mp-peering", TEXT).opt().mult(),
        ADMIN_C_OPT,
        TECH_C_OPT,
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static PERSON: ClassDef = class(
    "person",
    &[
        f("person", TEXT).lookup(),
        f("address", TEXT).mult(),
        f("phone", TEXT).mult(),
        f("fax-no", TEXT).opt().mult(),
        f("e-mail", EMAIL).mult(),
        f("nic-hdl", NIC_HDL).pkl(),
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static ROLE: ClassDef = class(
    "role",
    &[
        f("role", TEXT).lookup(),
        f("trouble", TEXT).opt().mult(),
        f("address", TEXT).mult(),
        f("phone", TEXT).mult(),
        f("fax-no", TEXT).opt().mult(),
        f("e-mail", EMAIL).mult(),
        ADMIN_C_OPT,
        TECH_C_OPT,
        f("nic-hdl", NIC_HDL).pkl(),
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static ROUTE: ClassDef = route_class(
    "route",
    &[
        f("route", FieldKind::Ipv4Prefix).pkl(),
        DESCR,
        f("origin", FieldKind::AsNumber).pk(),
        f("holes", FieldKind::Ipv4Prefixes).opt().mult(),
        f("member-of", weak_list(&["route-set"]))
            .lookup()
            .opt()
            .mult(),
        f("inject", TEXT).opt().mult(),
        f("aggr-bndry", TEXT).opt(),
        f("aggr-mtd", TEXT).opt(),
        f("export-comps", TEXT).opt(),
        f("components", TEXT).opt(),
        ADMIN_C_OPT,
        TECH_C_OPT,
        f("geoidx", TEXT).opt().mult(),
        f("roa-uri", TEXT).opt(),
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static ROUTE_SET: ClassDef = set_class(
    "route-set",
    &[
        f("route-set", FieldKind::SetName { prefix: "RS-" }).pkl(),
        f("members", FieldKind::RouteSetMembers { ip_version: 4 })
            .lookup()
            .opt()
            .mult(),
        f("mp-members", FieldKind::RouteSetMembers { ip_version: 0 })
            .lookup()
            .opt()
            .mult(),
        f("mbrs-by-ref", MBRS_BY_REF).lookup().opt().mult(),
        DESCR,
        ADMIN_C_OPT,
        TECH_C_OPT,
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static ROUTE6: ClassDef = route_class(
    "route6",
    &[
        f("route6", FieldKind::Ipv6Prefix).pkl(),
        DESCR,
        f("origin", FieldKind::AsNumber).pk(),
        f("holes", FieldKind::Ipv6Prefixes).opt().mult(),
        f("member-of", weak_list(&["route-set"]))
            .lookup()
            .opt()
            .mult(),
        f("inject", TEXT).opt().mult(),
        f("aggr-bndry", TEXT).opt(),
        f("aggr-mtd", TEXT).opt(),
        f("export-comps", TEXT).opt(),
        f("components", TEXT).opt(),
        ADMIN_C_OPT,
        TECH_C_OPT,
        f("geoidx", TEXT).opt().mult(),
        f("roa-uri", TEXT).opt(),
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

static RTR_SET: ClassDef = set_class(
    "rtr-set",
    &[
        f("rtr-set", FieldKind::SetName { prefix: "RTRS-" }).pkl(),
        DESCR,
        f("members", weak_list(&["inet-rtr", "rtr-set"]))
            .lookup()
            .opt()
            .mult(),
        f("mp-members", weak_list(&["inet-rtr", "rtr-set"]))
            .lookup()
            .opt()
            .mult(),
        f("mbrs-by-ref", MBRS_BY_REF).lookup().opt().mult(),
        ADMIN_C_OPT,
        TECH_C_OPT,
        REMARKS,
        NOTIFY,
        MNT_BY_F,
        CHANGED_F,
        SOURCE,
    ],
);

/// `OBJECT_CLASS_MAPPING`, in v4's order.
pub static OBJECT_CLASSES: [&ClassDef; 19] = [
    &AS_BLOCK,
    &AS_SET,
    &AUT_NUM,
    &DOMAIN,
    &FILTER_SET,
    &INET_RTR,
    &INET6NUM,
    &INETNUM,
    &IRT,
    &KEY_CERT,
    &MNTNER,
    &ORGANISATION,
    &PEERING_SET,
    &PERSON,
    &ROLE,
    &ROUTE,
    &ROUTE_SET,
    &ROUTE6,
    &RTR_SET,
];

/// Look up an object class by its exact (case-sensitive) name.
pub fn class_by_name(name: &str) -> Option<&'static ClassDef> {
    OBJECT_CLASSES.iter().copied().find(|c| c.name == name)
}

/// The field a reference to `class` is validated with: the one that is both
/// primary and look-up key (`RPSLReferenceField.resolve_references`).
pub(crate) fn identifier_field(class: &str) -> Option<&'static FieldDef> {
    class_by_name(class)?
        .fields
        .iter()
        .find(|f| f.primary_key && f.lookup_key)
}

/// `references_strong_inbound()`: attribute names under which other
/// objects refer to objects of `class` with a strong reference, sorted.
pub fn references_strong_inbound(class: &str) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for c in OBJECT_CLASSES {
        for field in c.fields {
            if field.kind.strong()
                && field.kind.referring().contains(&class)
                && !out.contains(&field.name)
            {
                out.push(field.name);
            }
        }
    }
    out.sort_unstable();
    out
}

/// `lookup_field_names()`: every look-up attribute that is not also part of
/// its class's primary key, plus `origin`, sorted.
pub fn lookup_field_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = vec!["origin"];
    for c in OBJECT_CLASSES {
        for field in c.fields {
            if field.lookup_key && !field.primary_key && !names.contains(&field.name) {
                names.push(field.name);
            }
        }
    }
    names.sort_unstable();
    names
}
