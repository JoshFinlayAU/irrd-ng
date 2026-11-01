//! `irrd/updates/validators.py`: references, authentication and other
//! rules for RPSL changes.

use std::collections::{HashMap, HashSet};

use rpsl::{RpslObject, Value};
use store::{AuthApiTokenRow, AuthMntnerRow, ChangeLogRow, Timestamp, Uuid, WriteTx};

use crate::messages;
use crate::settings::{AutnumAuthMode, SubmitSettings};
use crate::store_util::{self, Row};
use crate::{AuthMethod, Internal, Origin};

/// v4's logger.
pub(crate) const LOG_TARGET: &str = "irrd.updates.validators";

/// `MAX_CREDENTIALS_PER_SUBMISSION`
pub(crate) const MAX_CREDENTIALS_PER_SUBMISSION: usize = 20;

/// An `OrderedSet` of messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MessageSet(Vec<String>);

impl MessageSet {
    pub(crate) fn add(&mut self, m: String) {
        if !self.0.contains(&m) {
            self.0.push(m);
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &String> {
        self.0.iter()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// `ValidatorResult`
#[derive(Debug, Clone, Default)]
pub(crate) struct ValidatorResult {
    pub(crate) error_messages: MessageSet,
    pub(crate) info_messages: MessageSet,
    /// mntners that may need to be notified
    pub(crate) mntners_notify: Vec<RpslObject>,
    pub(crate) auth_method: AuthMethod,
    pub(crate) auth_through_mntner: Option<String>,
    pub(crate) auth_through_internal_mntner: Option<AuthMntnerRow>,
    pub(crate) auth_through_api_key: Option<AuthApiTokenRow>,
}

impl ValidatorResult {
    pub(crate) fn is_valid(&self) -> bool {
        self.error_messages.is_empty()
    }

    /// `to_change_log()`, before the caller fills the target fields.
    pub(crate) fn to_change_log(&self, now: Timestamp) -> ChangeLogRow {
        ChangeLogRow {
            pk: Uuid::new_v4(),
            auth_by_user_id: None,
            auth_by_user_email: None,
            auth_by_api_key_id: self.auth_through_api_key.as_ref().map(|k| k.pk),
            auth_by_api_key_id_fixed: self.auth_through_api_key.as_ref().map(|k| k.pk),
            auth_through_mntner_id: self.auth_through_internal_mntner.as_ref().map(|m| m.pk),
            auth_through_rpsl_mntner_pk: self.auth_through_mntner.clone(),
            auth_by_rpsl_mntner_password: self.auth_method == AuthMethod::MntnerPassword,
            auth_by_rpsl_mntner_pgp_key: self.auth_method == AuthMethod::MntnerPgpKey,
            auth_by_override: Some(self.auth_method.used_override()),
            from_email: None,
            from_ip: None,
            auth_change_descr: None,
            auth_affected_user_id: None,
            auth_affected_mntner_id: None,
            rpsl_target_request_type: None,
            rpsl_target_pk: None,
            rpsl_target_source: None,
            rpsl_target_object_class: None,
            rpsl_target_object_text_old: None,
            rpsl_target_object_text_new: None,
            timestamp: now,
        }
    }
}

/// `MntnerCheckResult`
#[derive(Debug, Clone, Default)]
struct MntnerCheckResult {
    valid: bool,
    associated_mntners: Vec<RpslObject>,
    auth_method: AuthMethod,
    mntner_pk: Option<String>,
    auth_mntner: Option<AuthMntnerRow>,
    api_key: Option<AuthApiTokenRow>,
}

/// A request as the reference validator needs to know it for preloading.
#[derive(Debug, Clone)]
pub(crate) struct PreloadItem {
    pub(crate) key: (String, String, String),
    pub(crate) request_type: Option<store::UpdateRequestType>,
}

/// `ReferenceValidator`
#[derive(Debug, Default)]
pub(crate) struct ReferenceValidator {
    cache: HashSet<(String, String, String)>,
    preloaded_new: HashSet<(String, String, String)>,
    preloaded_deleted: HashSet<(String, String, String)>,
}

impl ReferenceValidator {
    /// `preload(results)`
    pub(crate) fn preload(&mut self, items: &[PreloadItem]) {
        self.preloaded_new.clear();
        self.preloaded_deleted.clear();
        for i in items {
            match i.request_type {
                Some(store::UpdateRequestType::Delete) => {
                    self.preloaded_deleted.insert(i.key.clone());
                }
                Some(store::UpdateRequestType::Create | store::UpdateRequestType::Modify) => {
                    self.preloaded_new.insert(i.key.clone());
                }
                None => {}
            }
        }
    }

    /// `check_references_to_others(rpsl_obj)`
    pub(crate) fn check_references_to_others(
        &mut self,
        tx: &mut WriteTx<'_, '_>,
        obj: &RpslObject,
    ) -> Result<ValidatorResult, Internal> {
        let mut result = ValidatorResult::default();
        let source = store_util::source_of(obj)?;
        for (field, referred, values) in obj.referred_strong_objects() {
            let pks: Vec<String> = match values {
                Value::List(l) => l.clone(),
                // Iterating a str in Python yields its characters.
                Value::Str(s) => s.chars().map(String::from).collect(),
            };
            for pk in pks {
                if !self.check_reference_to_others(tx, referred, &pk, &source)? {
                    let referred_str = if referred.len() > 1 {
                        format!("one of {}", referred.join(", "))
                    } else {
                        referred[0].to_owned()
                    };
                    result.error_messages.add(messages::reference_not_found(
                        &pk,
                        field,
                        &source,
                        &referred_str,
                    ));
                }
            }
        }
        Ok(result)
    }

    fn check_reference_to_others(
        &mut self,
        tx: &mut WriteTx<'_, '_>,
        classes: &[&str],
        pk: &str,
        source: &str,
    ) -> Result<bool, Internal> {
        for class in classes {
            let key = ((*class).to_owned(), pk.to_owned(), source.to_owned());
            if self.cache.contains(&key) || self.preloaded_new.contains(&key) {
                return Ok(true);
            }
            if self.preloaded_deleted.contains(&key) {
                return Ok(false);
            }
        }
        let wanted = store_util::upper_strip(pk);
        let mut found = false;
        let view = tx.read()?;
        for class in classes {
            if view.object(source, class, &wanted)?.is_some() {
                self.cache
                    .insert(((*class).to_owned(), pk.to_owned(), source.to_owned()));
                found = true;
            }
        }
        Ok(found)
    }

    /// `check_references_from_others_for_deletion(rpsl_obj, used_override)`
    pub(crate) fn check_references_from_others_for_deletion(
        &self,
        tx: &mut WriteTx<'_, '_>,
        obj: &RpslObject,
        used_override: bool,
    ) -> Result<ValidatorResult, Internal> {
        let mut result = ValidatorResult::default();
        let protected =
            store::write::PROTECTED_NAME_OBJECT_CLASSES.contains(&obj.rpsl_object_class());
        let referring = self.references_from_others(tx, obj)?;
        for (class, pk) in referring {
            if used_override && protected {
                result
                    .info_messages
                    .add(messages::delete_reference_override(&obj.pk(), &class, &pk));
            } else {
                result.error_messages.add(messages::delete_still_referenced(
                    &obj.pk(),
                    &class,
                    &pk,
                ));
            }
        }
        Ok(result)
    }

    /// `check_protected_name(rpsl_obj, used_override)`
    pub(crate) fn check_protected_name(
        &self,
        tx: &mut WriteTx<'_, '_>,
        obj: &RpslObject,
        used_override: bool,
    ) -> Result<ValidatorResult, Internal> {
        let mut result = ValidatorResult::default();
        for (class, pk) in self.references_from_others(tx, obj)? {
            if used_override {
                result
                    .info_messages
                    .add(messages::create_references_override(&obj.pk(), &class, &pk));
            } else {
                result.error_messages.add(messages::create_references_exist(
                    &obj.pk(),
                    &class,
                    &pk,
                ));
            }
        }
        let source = store_util::source_of(obj)?;
        let is_protected = tx
            .read()?
            .protected_name(&source, &obj.pk())?
            .iter()
            .any(|p| p.object_class == obj.rpsl_object_class());
        if is_protected {
            if used_override {
                result
                    .info_messages
                    .add(messages::protected_name_override(&obj.pk()));
            } else {
                result
                    .error_messages
                    .add(messages::protected_name(&obj.pk()));
            }
        }
        Ok(result)
    }

    /// `_check_references_from_others`: (class, rpsl_pk) of every object in
    /// the source referring to `obj`, in v4's query order, except those
    /// about to be deleted.
    fn references_from_others(
        &self,
        tx: &mut WriteTx<'_, '_>,
        obj: &RpslObject,
    ) -> Result<Vec<(String, String)>, Internal> {
        let fields = obj.references_strong_inbound();
        if fields.is_empty() {
            return Ok(Vec::new());
        }
        let source = store_util::source_of(obj)?;
        let rows = store_util::lookup_attrs_in(tx, &source, &fields, &obj.pk())?;
        Ok(rows
            .into_iter()
            .filter(|r| {
                !self.preloaded_deleted.contains(&(
                    r.object_class.clone(),
                    r.rpsl_pk.clone(),
                    r.source.clone(),
                ))
            })
            .map(|r| (r.object_class, r.rpsl_pk))
            .collect())
    }
}

/// `AuthValidator`
#[derive(Debug)]
pub(crate) struct AuthValidator {
    pub(crate) passwords: Vec<String>,
    pub(crate) overrides: Vec<String>,
    pub(crate) api_keys: Vec<String>,
    pub(crate) origin: Origin,
    pub(crate) remote_ip: Option<rpsl::Ip>,
    pub(crate) keycert_obj_pk: Option<String>,
    mntner_db_cache: Vec<RpslObject>,
    pre_approved: HashSet<String>,
    related_route_cache: HashMap<String, Option<Row>>,
}

impl AuthValidator {
    /// `AuthValidator(database_handler, origin, keycert_obj_pk, remote_ip=...)`
    pub(crate) fn new(
        origin: Origin,
        keycert_obj_pk: Option<String>,
        remote_ip: Option<rpsl::Ip>,
    ) -> Self {
        AuthValidator {
            passwords: Vec::new(),
            overrides: Vec::new(),
            api_keys: Vec::new(),
            origin,
            remote_ip,
            keycert_obj_pk,
            mntner_db_cache: Vec::new(),
            pre_approved: HashSet::new(),
            related_route_cache: HashMap::new(),
        }
    }

    /// `pre_approve(presumed_valid_new_mntners)`
    pub(crate) fn pre_approve(&mut self, pks: Vec<String>) {
        self.pre_approved = pks.into_iter().collect();
    }

    /// `check_override()`
    pub(crate) fn check_override(&mut self, settings: &SubmitSettings) -> AuthMethod {
        let Some(hash) = settings
            .override_password
            .as_deref()
            .filter(|h| !h.is_empty())
        else {
            if !self.overrides.is_empty() {
                tracing::info!(target: LOG_TARGET, "Ignoring override password, auth.override_password not set.");
            }
            return AuthMethod::None;
        };
        dedupe(&mut self.overrides);
        if self.overrides.len() > MAX_CREDENTIALS_PER_SUBMISSION {
            tracing::info!(
                target: LOG_TARGET,
                "Ignoring override passwords: more than {MAX_CREDENTIALS_PER_SUBMISSION} distinct values in submission"
            );
            return AuthMethod::None;
        }
        for o in &self.overrides {
            match verify_override(o, hash) {
                Some(true) => return AuthMethod::OverridePassword,
                Some(false) => {
                    tracing::info!(target: LOG_TARGET, "Found invalid override password, ignoring.")
                }
                None => tracing::error!(
                    target: LOG_TARGET,
                    "Exception occurred while checking override password as both bcrypt and salted MD5 (possible misconfigured hash?)"
                ),
            }
        }
        AuthMethod::None
    }

    /// `process_auth(rpsl_obj_new, rpsl_obj_current)`
    pub(crate) fn process_auth(
        &mut self,
        tx: &mut WriteTx<'_, '_>,
        settings: &SubmitSettings,
        obj_new: &mut RpslObject,
        obj_current: Option<&RpslObject>,
    ) -> Result<ValidatorResult, Internal> {
        let source = store_util::source_of(obj_new)?;
        let mut result = ValidatorResult::default();

        let override_method = self.check_override(settings);
        if override_method != AuthMethod::None {
            result.auth_method = override_method;
            tracing::info!(target: LOG_TARGET, "Found valid override password.");
            return Ok(result);
        }

        dedupe(&mut self.passwords);
        if self.passwords.len() > MAX_CREDENTIALS_PER_SUBMISSION {
            result
                .error_messages
                .add(messages::too_many_passwords(MAX_CREDENTIALS_PER_SUBMISSION));
            return Ok(result);
        }

        let mntners_new = store_util::mnt_by(obj_new)?;
        let new_result = self.check_mntners(tx, settings, obj_new, &mntners_new, &source)?;
        if !new_result.valid {
            generate_failure_message(&mut result, &mntners_new, obj_new, None);
        }

        let mut current_result = None;
        let mut related_result = None;
        if let Some(current) = obj_current {
            let mntners_current = store_util::mnt_by(current)?;
            let r = self.check_mntners(tx, settings, obj_new, &mntners_current, &source)?;
            if !r.valid {
                generate_failure_message(&mut result, &mntners_current, obj_new, None);
            }
            result.mntners_notify = r.associated_mntners.clone();
            current_result = Some(r);
        } else {
            result.mntners_notify = new_result.associated_mntners.clone();
            if let Some((class, pk, list)) =
                self.find_related_mntners(tx, settings, obj_new, &mut result)?
            {
                let r = self.check_mntners(tx, settings, obj_new, &list, &source)?;
                if !r.valid {
                    generate_failure_message(&mut result, &list, obj_new, Some((&class, &pk)));
                    result.mntners_notify = r.associated_mntners.clone();
                }
                related_result = Some(r);
            }
        }

        if obj_new.rpsl_object_class() == "mntner" {
            if obj_current.is_none() {
                result
                    .error_messages
                    .add(messages::NEW_MNTNER_NEEDS_ADMIN.to_owned());
                return Ok(result);
            }
            if obj_new.all_hashes_dummy() {
                if self.passwords.len() == 1 {
                    obj_new.force_single_new_password(&self.passwords[0]);
                    result
                        .info_messages
                        .add(messages::DUMMY_HASHES_REPLACED.to_owned());
                } else {
                    result
                        .error_messages
                        .add(messages::DUMMY_HASHES_NEED_ONE_PASSWORD.to_owned());
                }
            } else if obj_new
                .verify_auth(
                    &self.passwords,
                    self.keycert_obj_pk.as_deref(),
                    &settings.rpsl,
                )
                .is_none()
            {
                result
                    .error_messages
                    .add(messages::MNTNER_AUTH_FAILED.to_owned());
            }
        }

        let for_change_log = current_result.or(related_result).unwrap_or(new_result);
        result.auth_method = for_change_log.auth_method;
        result.auth_through_mntner = for_change_log.mntner_pk;
        result.auth_through_api_key = for_change_log.api_key;
        result.auth_through_internal_mntner = for_change_log.auth_mntner;
        Ok(result)
    }

    /// `_check_mntners(rpsl_obj_new, mntner_pk_list, source)`
    fn check_mntners(
        &mut self,
        tx: &mut WriteTx<'_, '_>,
        settings: &SubmitSettings,
        obj_new: &RpslObject,
        mntner_pks: &[String],
        source: &str,
    ) -> Result<MntnerCheckResult, Internal> {
        let wanted: HashSet<&str> = mntner_pks.iter().map(String::as_str).collect();
        let mut mntner_objs: Vec<RpslObject> = self
            .mntner_db_cache
            .iter()
            .filter(|m| wanted.contains(m.pk().as_str()) && m.source().is_ok_and(|s| s == source))
            .cloned()
            .collect();
        let have: HashSet<String> = mntner_objs.iter().map(RpslObject::pk).collect();
        let mut to_resolve: Vec<&str> = mntner_pks
            .iter()
            .map(String::as_str)
            .filter(|p| !have.contains(*p))
            .collect();
        to_resolve.sort_unstable();
        to_resolve.dedup();
        if !to_resolve.is_empty() {
            let rows = store_util::objects_by_pks(tx, source, "mntner", &to_resolve)?;
            for row in rows {
                let obj = store_util::parse_stored(&row.object_text, settings)?;
                let key = (obj.pk(), store_util::source_of(&obj).unwrap_or_default());
                if !self
                    .mntner_db_cache
                    .iter()
                    .any(|m| (m.pk(), store_util::source_of(m).unwrap_or_default()) == key)
                {
                    self.mntner_db_cache.push(obj.clone());
                }
                mntner_objs.push(obj);
            }
        }

        for name in mntner_pks {
            if self.pre_approved.contains(name) {
                return Ok(MntnerCheckResult {
                    valid: true,
                    associated_mntners: mntner_objs,
                    auth_method: AuthMethod::MntnerInSameRequest,
                    mntner_pk: Some(name.clone()),
                    ..Default::default()
                });
            }
            if let Some((token, mntner)) =
                self.api_key_match_for_mntner(tx, obj_new, name, source)?
            {
                return Ok(MntnerCheckResult {
                    valid: true,
                    associated_mntners: mntner_objs,
                    auth_method: AuthMethod::MntnerApiKey,
                    auth_mntner: Some(mntner),
                    mntner_pk: Some(name.clone()),
                    api_key: Some(token),
                });
            }
        }

        for m in &mntner_objs {
            if let Some(scheme) = m.verify_auth(
                &self.passwords,
                self.keycert_obj_pk.as_deref(),
                &settings.rpsl,
            ) {
                let method = if scheme.contains("PGPKEY") {
                    AuthMethod::MntnerPgpKey
                } else {
                    AuthMethod::MntnerPassword
                };
                return Ok(MntnerCheckResult {
                    valid: true,
                    auth_method: method,
                    mntner_pk: Some(m.pk()),
                    associated_mntners: mntner_objs.clone(),
                    ..Default::default()
                });
            }
        }
        Ok(MntnerCheckResult {
            valid: false,
            associated_mntners: mntner_objs,
            ..Default::default()
        })
    }

    /// `_api_key_match_for_mntner(rpsl_obj_new, rpsl_pk, source)`
    fn api_key_match_for_mntner(
        &self,
        tx: &mut WriteTx<'_, '_>,
        obj_new: &RpslObject,
        rpsl_pk: &str,
        source: &str,
    ) -> Result<Option<(AuthApiTokenRow, AuthMntnerRow)>, Internal> {
        if self.api_keys.is_empty() || obj_new.rpsl_object_class() == "mntner" {
            return Ok(None);
        }
        let mut keys: Vec<Uuid> = Vec::new();
        for k in &self.api_keys {
            match crate::py_uuid(k) {
                Some(u) => keys.push(u),
                None => {
                    tracing::info!(target: LOG_TARGET, "Ignoring API key in submission: not a valid UUID")
                }
            }
        }
        if keys.is_empty() {
            return Ok(None);
        }
        let view = tx.read()?;
        let mntners: Vec<AuthMntnerRow> = view
            .auth_mntners()?
            .into_iter()
            .filter(|m| m.rpsl_mntner_pk == rpsl_pk && m.rpsl_mntner_source == source)
            .collect();
        for token in view.auth_api_tokens()? {
            let Some(t) = token.token else { continue };
            if !keys.contains(&t) {
                continue;
            }
            let Some(m) = mntners.iter().find(|m| Some(m.pk) == token.mntner_id) else {
                continue;
            };
            if self.token_valid_for(&token)? {
                tracing::info!(target: LOG_TARGET, "Authenticated through API token {} on mntner {rpsl_pk}", token.pk);
                return Ok(Some((token, m.clone())));
            }
        }
        Ok(None)
    }

    /// `AuthApiToken.valid_for(origin, remote_ip)`
    fn token_valid_for(&self, token: &AuthApiTokenRow) -> Result<bool, Internal> {
        let origin_ok = (token.enabled_webapi && self.origin == Origin::WebApi)
            || (token.enabled_email && self.origin == Origin::Email);
        if !origin_ok {
            return Ok(false);
        }
        if let Some(restriction) = token.ip_restriction.as_deref().filter(|r| !r.is_empty()) {
            for ip in restriction.split(',') {
                let net = rpsl::Ip::parse(ip, 0).map_err(|e| Internal(e.0))?;
                if let Some(remote) = &self.remote_ip
                    && ip_in(remote, &net)
                {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        Ok(true)
    }

    /// `_find_related_mntners(rpsl_obj_new, result)`
    fn find_related_mntners(
        &mut self,
        tx: &mut WriteTx<'_, '_>,
        settings: &SubmitSettings,
        obj_new: &RpslObject,
        result: &mut ValidatorResult,
    ) -> Result<Option<(String, String, Vec<String>)>, Internal> {
        let mut related: Option<Row> = None;
        if matches!(obj_new.rpsl_object_class(), "route" | "route6") {
            related = self.find_related_object_route(tx, settings, obj_new)?;
        }
        if obj_new.class().is_set {
            related = find_related_object_set(tx, settings, obj_new, result)?;
        }
        Ok(related.map(|r| {
            let mntners = r.list("mnt-by");
            (r.object_class, r.rpsl_pk, mntners)
        }))
    }

    /// `_find_related_object_route(rpsl_obj_new)`
    fn find_related_object_route(
        &mut self,
        tx: &mut WriteTx<'_, '_>,
        settings: &SubmitSettings,
        obj_new: &RpslObject,
    ) -> Result<Option<Row>, Internal> {
        if !settings.authenticate_parents_route_creation {
            return Ok(None);
        }
        let cache_key = obj_new.render_rpsl_text();
        if let Some(hit) = self.related_route_cache.get(&cache_key) {
            return Ok(hit.clone());
        }
        let source = store_util::source_of(obj_new)?;
        let Some(prefix) = obj_new.prefix else {
            return Ok(None);
        };
        let inetnum_class = if obj_new.rpsl_object_class() == "route" {
            "inetnum"
        } else {
            "inet6num"
        };
        let mut found = store_util::ip_exact(tx, &source, inetnum_class, &prefix)?;
        if found.is_none() {
            found = store_util::ip_less_specific_one_level(tx, &source, inetnum_class, &prefix)?;
        }
        if found.is_none() {
            found = store_util::ip_less_specific_one_level(
                tx,
                &source,
                obj_new.rpsl_object_class(),
                &prefix,
            )?;
        }
        self.related_route_cache.insert(cache_key, found.clone());
        Ok(found)
    }
}

/// `_find_related_object_set(rpsl_obj_new, result)`
fn find_related_object_set(
    tx: &mut WriteTx<'_, '_>,
    settings: &SubmitSettings,
    obj_new: &RpslObject,
    result: &mut ValidatorResult,
) -> Result<Option<Row>, Internal> {
    let Some(segment) = obj_new.pk_asn_segment.clone().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let mode = settings.autnum_mode(obj_new.rpsl_object_class());
    if mode == AutnumAuthMode::Disabled {
        return Ok(None);
    }
    let source = store_util::source_of(obj_new)?;
    let found = store_util::objects_by_pks(tx, &source, "aut-num", &[&segment])?
        .into_iter()
        .next();
    if found.is_none() && mode == AutnumAuthMode::Required {
        result
            .error_messages
            .add(messages::set_requires_autnum(&segment));
    }
    Ok(found)
}

/// `_generate_failure_message`
fn generate_failure_message(
    result: &mut ValidatorResult,
    mntners: &[String],
    obj: &RpslObject,
    parent: Option<(&str, &str)>,
) {
    result.error_messages.add(messages::auth_failed(
        obj.rpsl_object_class(),
        &obj.pk(),
        &mntners.join(", "),
        parent,
    ));
}

/// `list(dict.fromkeys(values))`
fn dedupe(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|v| seen.insert(v.clone()));
}

/// `bcrypt.verify(override, hash)`, falling back to `md5_crypt.verify` when
/// passlib raises `ValueError`; `None` when both raise.
fn verify_override(password: &str, hash: &str) -> Option<bool> {
    use rpsl::PasswordHasher;
    if password.contains('\0') {
        return None;
    }
    if hash.starts_with("$2") {
        return Some(rpsl::auth::verify_password(
            PasswordHasher::BcryptPw,
            password,
            hash,
        ));
    }
    if hash.starts_with("$1$") {
        return Some(rpsl::auth::verify_password(
            PasswordHasher::Md5Pw,
            password,
            hash,
        ));
    }
    None
}

/// IPy's `remote_ip in IP(net)`.
fn ip_in(ip: &rpsl::Ip, net: &rpsl::Ip) -> bool {
    if ip.version() != net.version() {
        return false;
    }
    let (n, b) = (net.net().int(), net.broadcast().int());
    let (a, z) = (ip.net().int(), ip.broadcast().int());
    n <= a && z <= b
}

/// `RulesValidator`
pub(crate) fn rules_validate(
    tx: &mut WriteTx<'_, '_>,
    obj: &RpslObject,
    request_type: store::UpdateRequestType,
) -> Result<ValidatorResult, Internal> {
    let mut result = ValidatorResult::default();
    if request_type != store::UpdateRequestType::Delete
        && obj.is_route()
        && let Some(prefix) = obj.prefix
    {
        let blocked = [
            ("0.0.0.0", 0u32, 4u8),
            ("0.0.0.0", 32, 4),
            ("::", 0, 6),
            ("::", 128, 6),
        ];
        if blocked.iter().any(|(_, len, v)| {
            prefix.version() == *v && prefix.int() == 0 && prefix.prefixlen() == *len
        }) {
            result
                .error_messages
                .add(messages::route_not_permitted(&prefix.to_string()));
        }
    }
    if obj.rpsl_object_class() == "mntner" {
        let source = store_util::source_of(obj)?;
        let pk = obj.pk();
        let view = tx.read()?;
        if request_type == store::UpdateRequestType::Create
            && view
                .suspended_objects()?
                .iter()
                .any(|s| s.object_class == "mntner" && s.rpsl_pk == pk && s.source == source)
        {
            result
                .error_messages
                .add(messages::suspended_mntner_exists(&pk, &source));
        }
        let is_migrated = view
            .auth_mntners()?
            .iter()
            .any(|m| m.rpsl_mntner_pk == pk && m.rpsl_mntner_source == source);
        let has_internal = obj.has_internal_auth();
        let method = rpsl::fields::RPSL_MNTNER_AUTH_INTERNAL;
        if is_migrated && !has_internal {
            result
                .error_messages
                .add(messages::mntner_migrated_needs_internal(method));
        } else if !is_migrated && has_internal {
            result
                .error_messages
                .add(messages::mntner_not_migrated(method));
        }
    }
    Ok(result)
}
