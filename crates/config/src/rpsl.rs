//! The [`rpsl::RpslSettings`] the parser needs, read from the configuration
//! with the same tests v4's RPSL code applies to `get_setting()`.

use std::collections::HashMap;

use rpsl::{HasherAvailability, RpslSettings, SourceRenderSettings};

use crate::{
    AUTH_SET_CREATION_COMMON_KEY, Configuration, PASSWORD_HASHERS, PyException, RPSL_SET_CLASSES,
    Value, messages,
};

impl Configuration {
    /// Build the parser settings. Environment overrides apply, as they do
    /// to every `get_setting()` in v4, so `IRRD_SOURCES_X_AUTHORITATIVE=0`
    /// is the string `"0"` and therefore true.
    ///
    /// v4 only raises on a bad password hasher value when an `auth:` line is
    /// checked; that can only come from an environment override, since the
    /// file is validated. irrd-ng raises it here, once, instead.
    pub fn rpsl_settings(&self) -> Result<RpslSettings, PyException> {
        self.rpsl_settings_with_env(&|k| std::env::var(k).ok())
    }

    /// [`Self::rpsl_settings`] with the environment supplied by the caller.
    pub fn rpsl_settings_with_env(
        &self,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<RpslSettings, PyException> {
        let setting = |name: &str| -> Option<Value> {
            self.get_setting_live_with_env(name, env)
                .ok()
                .flatten()
                .map(|v| v.into_owned())
        };
        let mut hashers = [HasherAvailability::Enabled; 3];
        for (slot, name) in hashers.iter_mut().zip(PASSWORD_HASHERS) {
            *slot = hasher_availability(setting(&format!("auth.password_hashers.{name}")))?;
        }
        let [crypt_pw, md5_pw, bcrypt_pw] = hashers;

        // rpsl_objects.py tests `get_setting(...) is False`: only a YAML
        // boolean false relaxes the prefix rule, never an environment string.
        let mut set_creation_prefix_required = HashMap::new();
        for class in RPSL_SET_CLASSES
            .iter()
            .chain([&AUTH_SET_CREATION_COMMON_KEY])
        {
            let value = setting(&format!("auth.set_creation.{class}.prefix_required"));
            if let Some(value) = value {
                let required = !matches!(value, Value::Bool(false));
                set_creation_prefix_required.insert((*class).to_owned(), required);
            }
        }

        // Source names are matched case-sensitively, as DottedDict does. v4
        // looks a source up when rendering, so an environment override for a
        // source missing from the file would count there; here it does not.
        let mut sources = HashMap::new();
        if let Some(Value::Dict(configured)) = self.user_config().get_str("sources") {
            for name in configured.keys().filter_map(Value::as_str) {
                let truthy = |key: &str| {
                    setting(&format!("sources.{name}.{key}")).is_some_and(|v| v.truthy())
                };
                sources.insert(
                    name.to_owned(),
                    SourceRenderSettings {
                        authoritative: truthy("authoritative"),
                        authoritative_retain_last_modified: truthy(
                            "authoritative_retain_last_modified",
                        ),
                    },
                );
            }
        }

        Ok(RpslSettings {
            crypt_pw,
            md5_pw,
            bcrypt_pw,
            set_creation_prefix_required,
            asdot_queries: setting("compatibility.asdot_queries").is_some_and(|v| v.truthy()),
            sources,
        })
    }
}

/// `getattr(PasswordHasherAvailability, setting.upper())`.
fn hasher_availability(value: Option<Value>) -> Result<HasherAvailability, PyException> {
    let value = value.unwrap_or(Value::None);
    let Some(text) = value.as_str() else {
        return Err(PyException::new(
            "AttributeError",
            messages::no_upper(value.type_name()),
        ));
    };
    match text.to_uppercase().as_str() {
        "ENABLED" => Ok(HasherAvailability::Enabled),
        "LEGACY" => Ok(HasherAvailability::Legacy),
        "DISABLED" => Ok(HasherAvailability::Disabled),
        other => Err(PyException::new(
            "AttributeError",
            messages::no_hasher_availability(other),
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::{Staging, check_source_with_fs};

    fn load(yaml: &str) -> Configuration {
        match check_source_with_fs("irrd.yaml", Ok(yaml.as_bytes().to_vec()), &|_| true) {
            Ok(Staging::Valid(live)) => Configuration {
                path: "irrd.yaml".to_owned(),
                live,
            },
            other => panic!("{other:?}"),
        }
    }

    fn harness() -> String {
        std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../parity/v4/irrd.yaml"
        ))
        .unwrap()
    }

    #[test]
    fn harness_config_gives_the_parser_defaults() {
        let settings = load(&harness()).rpsl_settings_with_env(&|_| None).unwrap();
        assert_eq!(settings, RpslSettings::default());
    }

    #[test]
    fn environment_strings_are_truthy_and_never_false() {
        let env = |k: &str| match k {
            "IRRD_SOURCES_TEST_AUTHORITATIVE_RETAIN_LAST_MODIFIED" => Some("0".to_owned()),
            "IRRD_AUTH_SET_CREATION_COMMON_PREFIX_REQUIRED" => Some("False".to_owned()),
            "IRRD_COMPATIBILITY_ASDOT_QUERIES" => Some(String::new()),
            "IRRD_AUTH_PASSWORD_HASHERS_MD5-PW" => Some("Disabled".to_owned()),
            _ => None,
        };
        let settings = load(&harness()).rpsl_settings_with_env(&env).unwrap();
        assert!(settings.sources["TEST"].authoritative_retain_last_modified);
        assert!(settings.set_creation_prefix_required["COMMON"]);
        assert!(!settings.asdot_queries);
        assert_eq!(settings.md5_pw, HasherAvailability::Disabled);
    }

    #[test]
    fn yaml_false_relaxes_the_prefix_rule_per_class() {
        let yaml = harness().replace(
            "      COMMON:\n",
            "      as-set:\n        prefix_required: false\n      COMMON:\n",
        );
        let settings = load(&yaml).rpsl_settings_with_env(&|_| None).unwrap();
        assert!(!settings.set_creation_prefix_required["as-set"]);
        assert!(settings.set_creation_prefix_required["COMMON"]);
        assert!(
            !settings
                .set_creation_prefix_required
                .contains_key("route-set")
        );
    }

    #[test]
    fn unknown_hasher_availability_raises_as_v4_does() {
        let env = |k: &str| (k == "IRRD_AUTH_PASSWORD_HASHERS_BCRYPT-PW").then(|| "on".to_owned());
        let err = load(&harness()).rpsl_settings_with_env(&env).unwrap_err();
        assert_eq!(err.kind, "AttributeError");
        assert_eq!(
            err.message,
            "type object 'PasswordHasherAvailability' has no attribute 'ON'"
        );
    }
}
