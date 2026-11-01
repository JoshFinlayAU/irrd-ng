//! `irrd/updates/parser.py`: `ChangeRequest`, `SuspensionRequest` and
//! `parse_change_requests`.

use rpsl::{Keyring, ParseError, ParseOptions, RpslObject};
use store::{JournalEntryOrigin, ScopeFilterStatus, UpdateRequestType, WriteTx};

use crate::meta::RequestMeta;
use crate::settings::SubmitSettings;
use crate::store_util::{self, attr_list, source_of};
use crate::validators::{
    AuthValidator, PreloadItem, ReferenceValidator, ValidatorResult, rules_validate,
};
use crate::{Internal, Status, messages, suspension};

/// v4's logger.
pub(crate) const LOG_TARGET: &str = "irrd.updates.parser";

/// `SuspensionRequestType`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspensionType {
    /// `suspend`
    Suspend,
    /// `reactivate`
    Reactivate,
}

impl SuspensionType {
    /// The enum value.
    pub fn value(self) -> &'static str {
        match self {
            SuspensionType::Suspend => "suspend",
            SuspensionType::Reactivate => "reactivate",
        }
    }
}

/// What the requests need while being processed.
pub(crate) struct Ctx<'a> {
    pub(crate) settings: &'a SubmitSettings,
    pub(crate) keyring: &'a Keyring,
    pub(crate) meta: &'a RequestMeta,
}

fn parse(text: &str, strict: bool, ctx: &Ctx<'_>) -> Result<Result<RpslObject, String>, Internal> {
    match rpsl::rpsl_object_from_text(
        text,
        &ParseOptions {
            strict,
            default_source: None,
            settings: &ctx.settings.rpsl,
            keyring: ctx.keyring,
        },
    ) {
        Ok(o) => Ok(Ok(o)),
        Err(e @ ParseError::UnknownClass { .. }) => Ok(Err(e.to_string())),
        Err(ParseError::Uncaught(m)) => Err(Internal(m)),
    }
}

fn update_type_str(t: Option<UpdateRequestType>) -> &'static str {
    match t {
        Some(UpdateRequestType::Create) => "create",
        Some(UpdateRequestType::Modify) => "modify",
        Some(UpdateRequestType::Delete) => "delete",
        None => "request",
    }
}

/// `str.title()` of the one-word request types.
fn title(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// `ChangeRequest`
#[derive(Debug)]
pub(crate) struct ChangeRequest {
    pub(crate) rpsl_text_submitted: String,
    pub(crate) rpsl_obj_new: Option<RpslObject>,
    pub(crate) rpsl_obj_current: Option<RpslObject>,
    pub(crate) status: Status,
    pub(crate) request_type: Option<UpdateRequestType>,
    pub(crate) error_messages: Vec<String>,
    pub(crate) info_messages: Vec<String>,
    auth_result: Option<ValidatorResult>,
    cached_roa_validity: Option<bool>,
    non_strict_mode: bool,
}

impl ChangeRequest {
    /// `ChangeRequest.__init__`
    pub(crate) fn new(
        text: &str,
        tx: &mut WriteTx<'_, '_>,
        ctx: &Ctx<'_>,
        delete_reason: Option<&str>,
    ) -> Result<ChangeRequest, Internal> {
        let mut r = ChangeRequest {
            rpsl_text_submitted: text.to_owned(),
            rpsl_obj_new: None,
            rpsl_obj_current: None,
            status: Status::Processing,
            request_type: None,
            error_messages: Vec::new(),
            info_messages: Vec::new(),
            auth_result: None,
            cached_roa_validity: None,
            non_strict_mode: false,
        };
        if delete_reason.is_some_and(|d| !d.is_empty()) {
            r.request_type = Some(UpdateRequestType::Delete);
        }
        match parse(text, true, ctx)? {
            Ok(mut obj) => {
                if let Ok(source) = obj.source() {
                    r.non_strict_mode = ctx.settings.source(source).non_strict_mode;
                }
                if r.non_strict_mode || r.request_type == Some(UpdateRequestType::Delete) {
                    match parse(text, false, ctx)? {
                        Ok(o) => obj = o,
                        Err(e) => return Err(Internal(e)),
                    }
                }
                if obj.messages().has_errors() {
                    r.status = Status::ErrorParsing;
                }
                r.error_messages = obj.messages().errors().map(str::to_owned).collect();
                r.info_messages = obj.messages().infos().map(str::to_owned).collect();
                tracing::debug!(target: LOG_TARGET, "Processing new ChangeRequest for object {obj}");
                r.rpsl_obj_new = Some(obj);
            }
            Err(msg) => {
                r.request_type = None;
                r.status = Status::ErrorUnknownClass;
                r.error_messages = vec![msg];
            }
        }

        if r.is_valid()
            && let Some(obj) = &r.rpsl_obj_new
        {
            let source = source_of(obj)?;
            let s = ctx.settings.source(&source);
            if !s.authoritative {
                r.error_messages.push(messages::not_authoritative(&source));
                r.status = Status::ErrorNonAuthoritive;
                return Ok(r);
            }
            if let Some(filter) = &s.object_class_filter
                && !filter.is_empty()
                && !filter.iter().any(|c| c == obj.rpsl_object_class())
            {
                r.error_messages
                    .push(messages::object_class_filtered(obj.rpsl_object_class()));
                r.status = Status::ErrorObjectFilter;
                return Ok(r);
            }
            r.retrieve_existing_version(tx, ctx)?;
        }

        if r.request_type == Some(UpdateRequestType::Delete) && r.rpsl_obj_current.is_none() {
            r.status = Status::ErrorParsing;
            r.error_messages.push(messages::DELETE_NOT_FOUND.to_owned());
        }
        Ok(r)
    }

    fn retrieve_existing_version(
        &mut self,
        tx: &mut WriteTx<'_, '_>,
        ctx: &Ctx<'_>,
    ) -> Result<(), Internal> {
        let Some(obj) = &self.rpsl_obj_new else {
            return Ok(());
        };
        let source = source_of(obj)?;
        let rows = store_util::objects_by_pks(tx, &source, obj.rpsl_object_class(), &[&obj.pk()])?;
        match rows.first() {
            None => {
                if self.request_type.is_none() {
                    self.request_type = Some(UpdateRequestType::Create);
                }
            }
            Some(row) => {
                if self.request_type.is_none() {
                    self.request_type = Some(UpdateRequestType::Modify);
                }
                self.rpsl_obj_current =
                    Some(store_util::parse_stored(&row.object_text, ctx.settings)?);
            }
        }
        Ok(())
    }

    /// `is_valid()`
    pub(crate) fn is_valid(&self) -> bool {
        matches!(self.status, Status::Saved | Status::Processing)
    }

    pub(crate) fn preload_item(&self) -> Option<PreloadItem> {
        let obj = self.rpsl_obj_new.as_ref()?;
        Some(PreloadItem {
            key: (
                obj.rpsl_object_class().to_owned(),
                obj.pk(),
                obj.source().unwrap_or_default().to_owned(),
            ),
            request_type: self.request_type,
        })
    }

    /// `save()`
    pub(crate) fn save(&mut self, tx: &mut WriteTx<'_, '_>, ctx: &Ctx<'_>) -> Result<(), Internal> {
        let Some(new) = &self.rpsl_obj_new else {
            return Err(Internal(
                "ChangeRequest can only be saved in status PROCESSING".to_owned(),
            ));
        };
        if self.status != Status::Processing {
            return Err(Internal(
                "ChangeRequest can only be saved in status PROCESSING".to_owned(),
            ));
        }
        let rpsl = &ctx.settings.rpsl;
        if self.request_type == Some(UpdateRequestType::Delete)
            && let Some(current) = &self.rpsl_obj_current
        {
            tracing::info!(target: LOG_TARGET, "Saving change for {new}: deleting current object");
            tx.delete_rpsl_object(
                &source_of(current)?,
                &current.pk(),
                current.rpsl_object_class(),
                JournalEntryOrigin::AuthChange,
                None,
                true,
            )?;
        } else if let Some(current) = &self.rpsl_obj_current
            && new.render_rpsl_text_with_last_modified(0, rpsl)
                == current.render_rpsl_text_with_last_modified(0, rpsl)
        {
            self.info_messages
                .push(messages::IDENTICAL_OBJECT.to_owned());
            tracing::info!(target: LOG_TARGET, "Not saving change for {new}: identical to current object");
            self.status = Status::Saved;
            return Ok(());
        } else {
            tracing::info!(target: LOG_TARGET, "Saving change for {new}: inserting/updating current object");
            let row = crate::new_object(new, rpsl, None, None)?;
            tx.upsert_rpsl_object(&row, JournalEntryOrigin::AuthChange, None, None)?;
        }

        if let Some(auth) = &self.auth_result {
            let mut log = auth.to_change_log(tx.transaction_time());
            log.from_ip = ctx.meta.get_str(crate::META_KEY_HTTP_CLIENT_IP);
            log.from_email = ctx.meta.get_str("From");
            log.rpsl_target_request_type = self.request_type;
            log.rpsl_target_pk = Some(new.pk());
            log.rpsl_target_source = Some(source_of(new)?);
            log.rpsl_target_object_class = Some(new.rpsl_object_class().to_owned());
            if let Some(current) = &self.rpsl_obj_current {
                log.rpsl_target_object_text_old = Some(current.render_rpsl_text());
            }
            if self.request_type != Some(UpdateRequestType::Delete) {
                log.rpsl_target_object_text_new = Some(new.render_rpsl_text());
            }
            tx.put_change_log(&log)?;
        }
        self.status = Status::Saved;
        Ok(())
    }

    /// `submitter_report_human()`
    pub(crate) fn submitter_report_human(&self) -> String {
        let status = if self.is_valid() {
            "succeeded"
        } else {
            "FAILED"
        };
        let mut report = format!(
            "{} {status}: [{}] {}\n",
            title(update_type_str(self.request_type)),
            self.object_class_str(),
            self.object_pk_str()
        );
        if !self.info_messages.is_empty() || !self.error_messages.is_empty() {
            match (&self.rpsl_obj_new, self.error_messages.is_empty()) {
                (Some(obj), true) => {
                    report.push('\n');
                    report.push_str(&rpsl::text::remove_auth_hashes(&obj.render_rpsl_text()));
                    report.push('\n');
                }
                _ => {
                    report.push('\n');
                    report.push_str(&rpsl::text::remove_auth_hashes(&self.rpsl_text_submitted));
                    report.push('\n');
                }
            }
            for e in &self.error_messages {
                report.push_str(&format!("ERROR: {e}\n"));
            }
            for i in &self.info_messages {
                report.push_str(&format!("INFO: {i}\n"));
            }
        }
        report
    }

    /// `submitter_report_json()`
    pub(crate) fn submitter_report_json(&self) -> crate::json::Obj {
        let new_text = match (&self.rpsl_obj_new, self.error_messages.is_empty()) {
            (Some(o), true) => Some(o.render_rpsl_text()),
            _ => None,
        };
        let remove = |s: &str| -> String {
            if s.is_empty() {
                String::new()
            } else {
                rpsl::text::remove_auth_hashes(s).into_owned()
            }
        };
        let mut o = crate::json::Obj::new();
        o.bool("successful", self.is_valid());
        o.opt_str(
            "type",
            self.request_type
                .map(|t| update_type_str(Some(t)).to_owned()),
        );
        o.str("object_class", &self.object_class_str());
        o.str("rpsl_pk", &self.object_pk_str());
        o.str_list("info_messages", &self.info_messages);
        o.str_list("error_messages", &self.error_messages);
        o.opt_str("new_object_text", new_text.as_deref().map(remove));
        o.str("submitted_object_text", &remove(&self.rpsl_text_submitted));
        o
    }

    /// `notification_target_report()`
    pub(crate) fn notification_target_report(&self) -> String {
        let status = if self.is_valid() {
            "succeeded"
        } else {
            "FAILED AUTHORISATION"
        };
        let mut report = format!(
            "{} {status} for object below: [{}] {}:\n\n",
            title(update_type_str(self.request_type)),
            self.object_class_str(),
            self.object_pk_str()
        );
        let new_text = self
            .rpsl_obj_new
            .as_ref()
            .map(RpslObject::render_rpsl_text)
            .unwrap_or_default();
        if self.request_type == Some(UpdateRequestType::Modify) {
            let current_text = self
                .rpsl_obj_current
                .as_ref()
                .map(RpslObject::render_rpsl_text)
                .unwrap_or_default();
            let a: Vec<&str> = rpsl::splitline_unicodesafe(&current_text).collect();
            let b: Vec<&str> = rpsl::splitline_unicodesafe(&new_text).collect();
            let diff = crate::difflib::unified_diff(&a, &b);
            report.push_str(&diff.get(2..).unwrap_or_default().join("\n"));
            if self.status == Status::ErrorAuth {
                report.push_str("\n\n*Rejected* new version of this object:\n\n");
            } else {
                report.push_str("\n\nNew version of this object:\n\n");
            }
        }
        if self.request_type == Some(UpdateRequestType::Delete) {
            if let Some(c) = &self.rpsl_obj_current {
                report.push_str(&c.render_rpsl_text());
            }
        } else {
            report.push_str(&new_text);
        }
        rpsl::text::remove_auth_hashes(&report).into_owned()
    }

    pub(crate) fn object_pk_str(&self) -> String {
        self.rpsl_obj_new
            .as_ref()
            .map_or_else(|| messages::UNREADABLE_KEY.to_owned(), RpslObject::pk)
    }

    pub(crate) fn object_class_str(&self) -> String {
        self.rpsl_obj_new.as_ref().map_or_else(
            || messages::UNREADABLE_CLASS.to_owned(),
            |o| o.rpsl_object_class().to_owned(),
        )
    }

    /// `notification_targets()`, in first-seen order (v4 returns a set).
    pub(crate) fn notification_targets(&self) -> Vec<String> {
        let mut targets: Vec<String> = Vec::new();
        let qualifies = self.is_valid() || self.status == Status::ErrorAuth;
        let used_override = self
            .auth_result
            .as_ref()
            .is_some_and(|a| a.auth_method.used_override());
        if used_override || !qualifies {
            return targets;
        }
        let attr = if self.status == Status::ErrorAuth {
            "upd-to"
        } else {
            "mnt-nfy"
        };
        let mut add = |e: String| {
            if !targets.contains(&e) {
                targets.push(e);
            }
        };
        if let Some(a) = &self.auth_result {
            for m in &a.mntners_notify {
                for e in attr_list(m, attr) {
                    add(e);
                }
            }
        }
        if let Some(c) = &self.rpsl_obj_current {
            for e in attr_list(c, "notify") {
                add(e);
            }
        }
        targets
    }

    /// `validate()`
    pub(crate) fn validate(
        &mut self,
        tx: &mut WriteTx<'_, '_>,
        ctx: &Ctx<'_>,
        auth: &mut AuthValidator,
        refs: &mut ReferenceValidator,
    ) -> Result<bool, Internal> {
        if self.request_type == Some(UpdateRequestType::Create)
            && let Some(obj) = &mut self.rpsl_obj_new
            && !obj.clean_for_create(&ctx.settings.rpsl)
        {
            self.error_messages
                .extend(obj.messages().errors().map(str::to_owned));
            self.status = Status::ErrorParsing;
            return Ok(false);
        }
        if let Some(obj) = &self.rpsl_obj_new
            && let Some(t) = self.request_type
            && t != UpdateRequestType::Delete
        {
            let r = rules_validate(tx, obj, t)?;
            self.info_messages.extend(r.info_messages.iter().cloned());
            self.error_messages.extend(r.error_messages.iter().cloned());
            if !r.is_valid() {
                self.status = Status::ErrorRules;
                return Ok(false);
            }
        }
        if !self.check_auth(tx, ctx, auth)? {
            return Ok(false);
        }
        let references_valid = self.check_references(tx, refs)?;
        let protected_valid = self.check_protected_names(tx, refs)?;
        let rpki_valid = self.check_conflicting_roa(tx, ctx)?;
        let scope_valid = self.check_scopefilter(ctx)?;
        Ok(references_valid && rpki_valid && scope_valid && protected_valid)
    }

    fn used_override(&self) -> bool {
        self.auth_result
            .as_ref()
            .is_some_and(|a| a.auth_method.used_override())
    }

    fn check_auth(
        &mut self,
        tx: &mut WriteTx<'_, '_>,
        ctx: &Ctx<'_>,
        auth: &mut AuthValidator,
    ) -> Result<bool, Internal> {
        let Some(obj) = &mut self.rpsl_obj_new else {
            return Err(Internal("AssertionError".to_owned()));
        };
        let result = auth.process_auth(tx, ctx.settings, obj, self.rpsl_obj_current.as_ref())?;
        self.info_messages
            .extend(result.info_messages.iter().cloned());
        let valid = result.is_valid();
        if !valid {
            self.status = Status::ErrorAuth;
            self.error_messages
                .extend(result.error_messages.iter().cloned());
        }
        self.auth_result = Some(result);
        Ok(valid)
    }

    fn check_references(
        &mut self,
        tx: &mut WriteTx<'_, '_>,
        refs: &mut ReferenceValidator,
    ) -> Result<bool, Internal> {
        if self.non_strict_mode {
            return Ok(true);
        }
        let used_override = self.used_override();
        let result = match (&self.rpsl_obj_current, self.request_type) {
            (Some(current), Some(UpdateRequestType::Delete)) => {
                refs.check_references_from_others_for_deletion(tx, current, used_override)?
            }
            _ => match &self.rpsl_obj_new {
                Some(new) => refs.check_references_to_others(tx, new)?,
                None => return Err(Internal("AssertionError".to_owned())),
            },
        };
        self.info_messages
            .extend(result.info_messages.iter().cloned());
        if !result.is_valid() {
            self.error_messages
                .extend(result.error_messages.iter().cloned());
            if self.is_valid() {
                self.status = Status::ErrorReference;
            }
            return Ok(false);
        }
        Ok(true)
    }

    fn check_protected_names(
        &mut self,
        tx: &mut WriteTx<'_, '_>,
        refs: &ReferenceValidator,
    ) -> Result<bool, Internal> {
        if self.request_type == Some(UpdateRequestType::Create)
            && let Some(new) = &self.rpsl_obj_new
        {
            let result = refs.check_protected_name(tx, new, self.used_override())?;
            self.info_messages
                .extend(result.info_messages.iter().cloned());
            if !result.is_valid() {
                self.error_messages
                    .extend(result.error_messages.iter().cloned());
                if self.is_valid() {
                    self.status = Status::ErrorProtectedName;
                }
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn check_conflicting_roa(
        &mut self,
        tx: &mut WriteTx<'_, '_>,
        ctx: &Ctx<'_>,
    ) -> Result<bool, Internal> {
        let Some(new) = &self.rpsl_obj_new else {
            return Err(Internal("AssertionError".to_owned()));
        };
        if let Some(cached) = self.cached_roa_validity {
            return Ok(cached);
        }
        if !ctx.settings.rpki_enabled || !new.is_route() {
            return Ok(true);
        }
        if self.request_type == Some(UpdateRequestType::Delete) {
            return Ok(true);
        }
        let source = source_of(new)?;
        let (Some(prefix), Some(asn)) = (new.prefix, new.asn_first) else {
            return Err(Internal("AssertionError".to_owned()));
        };
        let Some(route) = store_util::store_prefix(&prefix) else {
            return Err(Internal("invalid prefix".to_owned()));
        };
        let excluded = ctx.settings.source(&source).rpki_excluded;
        let status = {
            let view = tx.read()?;
            rpki::validate_route_single(&view, &route, asn, excluded)?
        };
        if status == store::RpkiStatus::Invalid {
            if self.is_valid() {
                self.status = Status::ErrorRoa;
            }
            self.error_messages
                .push(messages::roa_conflict(&ctx.settings.roa_import_timer));
            self.cached_roa_validity = Some(false);
            return Ok(false);
        }
        self.cached_roa_validity = Some(true);
        Ok(true)
    }

    fn check_scopefilter(&mut self, ctx: &Ctx<'_>) -> Result<bool, Internal> {
        if self.request_type == Some(UpdateRequestType::Delete) {
            return Ok(true);
        }
        let Some(new) = &self.rpsl_obj_new else {
            return Ok(true);
        };
        let (status, comment) = crate::scope_status(ctx.settings, new)?;
        if matches!(
            status,
            ScopeFilterStatus::OutScopePrefix | ScopeFilterStatus::OutScopeAs
        ) {
            let message = messages::out_of_scope(&comment);
            if self.request_type == Some(UpdateRequestType::Create) {
                if self.is_valid() {
                    self.status = Status::ErrorScopefilter;
                }
                self.error_messages.push(message);
                return Ok(false);
            } else if self.request_type == Some(UpdateRequestType::Modify) {
                self.info_messages.push(message);
            }
        }
        Ok(true)
    }
}

/// `SuspensionRequest`
#[derive(Debug)]
pub(crate) struct SuspensionRequest {
    pub(crate) rpsl_text_submitted: String,
    pub(crate) rpsl_obj_new: Option<RpslObject>,
    pub(crate) status: Status,
    pub(crate) request_type: Option<SuspensionType>,
    pub(crate) error_messages: Vec<String>,
    pub(crate) info_messages: Vec<String>,
}

impl SuspensionRequest {
    /// `SuspensionRequest.__init__`
    pub(crate) fn new(text: &str, ctx: &Ctx<'_>, state: &str) -> Result<Self, Internal> {
        let mut r = SuspensionRequest {
            rpsl_text_submitted: text.to_owned(),
            rpsl_obj_new: None,
            status: Status::Processing,
            request_type: None,
            error_messages: Vec::new(),
            info_messages: Vec::new(),
        };
        r.request_type = match rpsl::python::upper(state).as_ref() {
            "SUSPEND" => Some(SuspensionType::Suspend),
            "REACTIVATE" => Some(SuspensionType::Reactivate),
            _ => {
                r.status = Status::ErrorParsing;
                r.error_messages = vec![messages::unknown_suspension_type(state)];
                return Ok(r);
            }
        };
        match parse(text, false, ctx)? {
            Ok(obj) => {
                if obj.messages().has_errors() {
                    r.status = Status::ErrorParsing;
                }
                r.error_messages = obj.messages().errors().map(str::to_owned).collect();
                r.info_messages = obj.messages().infos().map(str::to_owned).collect();
                r.rpsl_obj_new = Some(obj);
            }
            Err(msg) => {
                r.status = Status::ErrorUnknownClass;
                r.error_messages = vec![msg];
            }
        }
        let Some(obj) = &r.rpsl_obj_new else {
            return Ok(r);
        };
        if !r.error_messages.is_empty() {
            return Ok(r);
        }
        let source = source_of(obj)?;
        if !ctx.settings.source(&source).suspension_enabled {
            r.error_messages
                .push(messages::suspension_not_enabled(&source));
            r.status = Status::ErrorNonAuthoritive;
            return Ok(r);
        }
        if obj.rpsl_object_class() != "mntner" {
            r.error_messages
                .push(messages::SUSPENSION_MNTNER_ONLY.to_owned());
            r.status = Status::ErrorParsing;
        }
        Ok(r)
    }

    /// `save()`
    pub(crate) fn save(&mut self, tx: &mut WriteTx<'_, '_>, ctx: &Ctx<'_>) -> Result<(), Internal> {
        let Some(mntner) = &self.rpsl_obj_new else {
            return Err(Internal(
                "SuspensionRequest can only be saved in status PROCESSING".to_owned(),
            ));
        };
        if self.status != Status::Processing {
            return Err(Internal(
                "SuspensionRequest can only be saved in status PROCESSING".to_owned(),
            ));
        }
        let outcome = match self.request_type {
            Some(SuspensionType::Suspend) => {
                tracing::info!(target: LOG_TARGET, "Suspending mntner {mntner}");
                suspension::suspend_for_mntner(tx, ctx.settings, mntner).map(|rows| {
                    self.info_messages.extend(
                        rows.iter()
                            .map(|r| messages::suspended(&r.object_class, &r.rpsl_pk, &r.source)),
                    );
                })
            }
            Some(SuspensionType::Reactivate) => {
                tracing::info!(target: LOG_TARGET, "Reactivating mntner {mntner}");
                suspension::reactivate_for_mntner(tx, ctx.settings, mntner).map(
                    |(restored, infos)| {
                        self.info_messages.extend(infos);
                        self.info_messages
                            .extend(restored.iter().map(|r| messages::restored(r)));
                    },
                )
            }
            None => Ok(()),
        };
        match outcome {
            Ok(()) => {}
            Err(suspension::SuspensionError::Value(m)) => {
                self.status = Status::ErrorParsing;
                self.error_messages.push(m);
                return Ok(());
            }
            Err(suspension::SuspensionError::Internal(e)) => return Err(e),
        }
        self.status = Status::Saved;
        Ok(())
    }

    /// `is_valid()`, which in v4 re-runs `validate()` every time.
    pub(crate) fn is_valid(&mut self, auth: &mut AuthValidator, ctx: &Ctx<'_>) -> bool {
        self.validate(auth, ctx);
        matches!(self.status, Status::Saved | Status::Processing)
    }

    /// `validate()`
    pub(crate) fn validate(&mut self, auth: &mut AuthValidator, ctx: &Ctx<'_>) -> bool {
        if auth.check_override(ctx.settings) == crate::AuthMethod::None {
            self.status = Status::ErrorAuth;
            self.error_messages
                .push(messages::SUSPENSION_OVERRIDE_INVALID.to_owned());
            return false;
        }
        true
    }

    fn type_str(&self) -> &'static str {
        self.request_type.map_or("request", SuspensionType::value)
    }

    pub(crate) fn object_pk_str(&self) -> String {
        self.rpsl_obj_new
            .as_ref()
            .map_or_else(|| messages::UNREADABLE_KEY.to_owned(), RpslObject::pk)
    }

    pub(crate) fn object_class_str(&self) -> String {
        self.rpsl_obj_new.as_ref().map_or_else(
            || messages::UNREADABLE_CLASS.to_owned(),
            |o| o.rpsl_object_class().to_owned(),
        )
    }

    /// `submitter_report_human()`
    pub(crate) fn submitter_report_human(
        &mut self,
        auth: &mut AuthValidator,
        ctx: &Ctx<'_>,
    ) -> String {
        let status = if self.is_valid(auth, ctx) {
            "succeeded"
        } else {
            "FAILED"
        };
        let mut report = format!(
            "{} {status}: [{}] {}\n",
            title(self.type_str()),
            self.object_class_str(),
            self.object_pk_str()
        );
        if !self.info_messages.is_empty() || !self.error_messages.is_empty() {
            if !self.error_messages.is_empty() {
                report.push('\n');
                report.push_str(&self.rpsl_text_submitted);
                report.push('\n');
            }
            for e in &self.error_messages {
                report.push_str(&format!("ERROR: {e}\n"));
            }
            for i in &self.info_messages {
                report.push_str(&format!("INFO: {i}\n"));
            }
        }
        report
    }

    /// `submitter_report_json()`
    pub(crate) fn submitter_report_json(
        &mut self,
        auth: &mut AuthValidator,
        ctx: &Ctx<'_>,
    ) -> crate::json::Obj {
        let mut o = crate::json::Obj::new();
        o.bool("successful", self.is_valid(auth, ctx));
        o.opt_str("type", self.request_type.map(|t| t.value().to_owned()));
        o.str("object_class", &self.object_class_str());
        o.str("rpsl_pk", &self.object_pk_str());
        o.str_list("info_messages", &self.info_messages);
        o.str_list("error_messages", &self.error_messages);
        o
    }
}

/// A `ChangeRequest` or a `SuspensionRequest`.
#[derive(Debug)]
pub(crate) enum Request {
    /// A change.
    Change(Box<ChangeRequest>),
    /// A suspension or reactivation.
    Suspension(Box<SuspensionRequest>),
}

impl Request {
    pub(crate) fn status(&self) -> Status {
        match self {
            Request::Change(c) => c.status,
            Request::Suspension(s) => s.status,
        }
    }

    /// The request type as v4's report counters see it: only `ChangeRequest`
    /// types match `UpdateRequestType`.
    pub(crate) fn update_type(&self) -> Option<UpdateRequestType> {
        match self {
            Request::Change(c) => c.request_type,
            Request::Suspension(_) => None,
        }
    }

    pub(crate) fn is_valid(&mut self, auth: &mut AuthValidator, ctx: &Ctx<'_>) -> bool {
        match self {
            Request::Change(c) => c.is_valid(),
            Request::Suspension(s) => s.is_valid(auth, ctx),
        }
    }

    pub(crate) fn object_repr(&self) -> String {
        let obj = match self {
            Request::Change(c) => c.rpsl_obj_new.as_ref(),
            Request::Suspension(s) => s.rpsl_obj_new.as_ref(),
        };
        obj.map_or_else(|| "None".to_owned(), ToString::to_string)
    }
}

/// `parse_change_requests(requests_text, ...)`: the requests, and the
/// passwords, overrides and API keys found in the text.
pub(crate) fn parse_change_requests(
    text: &str,
    tx: &mut WriteTx<'_, '_>,
    ctx: &Ctx<'_>,
    auth: &mut AuthValidator,
) -> Result<Vec<Request>, Internal> {
    let mut results = Vec::new();
    let mut passwords = Vec::new();
    let mut overrides = Vec::new();
    let mut api_keys = Vec::new();
    let text = text.replace('\r', "");
    for object_text in text.split("\n\n") {
        let object_text = rpsl::python::strip(object_text);
        if object_text.is_empty() {
            continue;
        }
        let mut rpsl_text = String::new();
        let mut delete_reason: Option<String> = None;
        let mut suspension_state: Option<String> = None;
        for line in rpsl::splitline_unicodesafe(object_text) {
            let value =
                || rpsl::python::strip(line.split_once(':').map_or("", |(_, v)| v)).to_owned();
            if line.starts_with("password:") {
                passwords.push(value());
            } else if line.starts_with("override:") {
                overrides.push(value());
            } else if line.starts_with("api-key:") {
                api_keys.push(value());
            } else if line.starts_with("delete:") {
                delete_reason = Some(value());
            } else if line.starts_with("suspension:") {
                suspension_state = Some(value());
            } else {
                rpsl_text.push_str(line);
                rpsl_text.push('\n');
            }
        }
        if rpsl_text.is_empty() {
            continue;
        }
        match suspension_state.filter(|s| !s.is_empty()) {
            Some(state) => results.push(Request::Suspension(Box::new(SuspensionRequest::new(
                &rpsl_text, ctx, &state,
            )?))),
            None => results.push(Request::Change(Box::new(ChangeRequest::new(
                &rpsl_text,
                tx,
                ctx,
                delete_reason.as_deref(),
            )?))),
        }
    }
    auth.passwords = passwords;
    auth.overrides = overrides;
    auth.api_keys = api_keys;
    Ok(results)
}
