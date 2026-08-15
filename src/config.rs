//! Operator-supplied configuration schema for `dev.mcpg.identity.ldap`.
//!
//! One plugin instance verifies callers against one directory. The bind
//! strategy is a tagged union ([`BindMode`]): `direct` templates the
//! caller's DN, `search` looks the caller up with a service account first
//! (the Active-Directory-friendly mode).

use serde::Deserialize;
use thiserror::Error;

/// Placeholder substituted with the caller's username in DN templates and
/// search filters. Escaped per its context before substitution (RFC 4514
/// for DNs, RFC 4515 for filters).
pub const USERNAME_PLACEHOLDER: &str = "{username}";

/// Top-level plugin config.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdapIdentityConfig {
    /// `ldap://host:389` or `ldaps://host:636`. Operator-configured.
    pub url: String,

    /// How the caller's username + password are verified against the
    /// directory.
    pub bind: BindMode,

    /// Attribute holding the caller's group memberships (values are full
    /// group DNs). Default `memberOf` — AD and most modern directories.
    #[serde(default = "default_group_attribute")]
    pub group_attribute: String,

    /// Also map each group DN's first RDN value (its CN) into `roles`,
    /// alongside the full DN kept in `groups`. Gives friendly role names
    /// (`cn=admins,ou=groups,dc=x` → `admins`). Default `true`.
    #[serde(default = "default_true")]
    pub roles_from_group_cn: bool,

    /// Directory attribute to use as the resolved `subject_id`. Default
    /// none → the caller's bound DN is the subject.
    #[serde(default)]
    pub subject_attribute: Option<String>,

    /// Extra directory attributes to copy onto the identity's `attributes`
    /// map (first value of each).
    #[serde(default)]
    pub attributes: Vec<String>,

    /// Cap on group / role values projected onto the identity.
    #[serde(default = "default_size_limit")]
    pub size_limit: usize,

    /// connect + bind + search timeout (ms). Default 10 s.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Trust level + provider label applied to resolved identities.
    #[serde(default)]
    pub resolution: ResolutionConfig,
}

/// Bind strategy — how the caller's password is verified.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum BindMode {
    /// Build the caller's DN from a template, then simple-bind it with the
    /// caller's password. Simplest; needs predictable DNs. `{username}` is
    /// substituted (RFC 4514 DN-escaped).
    Direct {
        /// e.g. `uid={username},ou=people,dc=example,dc=org`.
        user_dn_template: String,
        /// Base DN to read group memberships from. Default: the bound user
        /// DN itself (a base-scoped read of the user's own entry).
        #[serde(default)]
        groups_base_dn: Option<String>,
    },
    /// Bind a service account, search for the caller by filter, then re-bind
    /// as the matched DN with the caller's password. The
    /// Active-Directory-friendly mode (DNs aren't predictable).
    Search {
        /// Service-account bind DN.
        bind_dn: String,
        /// Service-account password — a literal, already resolved by the
        /// gateway secret-resolver (`${env.X}` / `vault://...` /
        /// `file://...`). Never a plaintext secret in committed config.
        bind_password: String,
        /// Search base for the user lookup.
        base_dn: String,
        /// Filter selecting the caller. `{username}` is substituted (RFC
        /// 4515 filter-escaped). e.g. `(sAMAccountName={username})` (AD) or
        /// `(uid={username})`.
        user_filter: String,
    },
}

/// Trust posture applied to successfully bound callers.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionConfig {
    /// Trust level the gateway associates with a successfully bound caller.
    /// A successful directory bind is cryptographic proof the caller holds
    /// the password, so `"verified"` is the natural default; operators on
    /// weaker contracts downgrade to `"header_asserted"`.
    #[serde(default = "default_trust_level")]
    pub trust_level: String,

    /// `auth_provider` label on the resolved `PluginIdentity`.
    #[serde(default = "default_auth_provider_label")]
    pub auth_provider_label: String,
}

impl Default for ResolutionConfig {
    fn default() -> Self {
        Self {
            trust_level: default_trust_level(),
            auth_provider_label: default_auth_provider_label(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_group_attribute() -> String {
    "memberOf".into()
}
fn default_size_limit() -> usize {
    100
}
fn default_timeout_ms() -> u64 {
    10_000
}
fn default_trust_level() -> String {
    "verified".into()
}
fn default_auth_provider_label() -> String {
    "ldap".into()
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid identity.ldap config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("identity.ldap: url must start with ldap:// or ldaps://, got `{0}`")]
    InvalidUrl(String),
    #[error("identity.ldap: {field} must not be empty")]
    Empty { field: &'static str },
    #[error(
        "identity.ldap: {field} must contain the `{placeholder}` placeholder \
         (it is substituted with the caller's username)"
    )]
    MissingUsernamePlaceholder {
        field: &'static str,
        placeholder: &'static str,
    },
    #[error("identity.ldap: timeout_ms must be greater than 0")]
    ZeroTimeout,
    #[error("identity.ldap: size_limit must be greater than 0")]
    ZeroSizeLimit,
    #[error("identity.ldap: invalid trust_level `{0}` (allowed: verified | header_asserted)")]
    InvalidTrustLevel(String),
}

impl LdapIdentityConfig {
    /// Parse + validate from JSON.
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !self.url.starts_with("ldap://") && !self.url.starts_with("ldaps://") {
            return Err(ConfigError::InvalidUrl(self.url.clone()));
        }
        if self.group_attribute.trim().is_empty() {
            return Err(ConfigError::Empty {
                field: "group_attribute",
            });
        }
        if self.timeout_ms == 0 {
            return Err(ConfigError::ZeroTimeout);
        }
        if self.size_limit == 0 {
            return Err(ConfigError::ZeroSizeLimit);
        }
        match self.resolution.trust_level.as_str() {
            "verified" | "header_asserted" => {}
            other => return Err(ConfigError::InvalidTrustLevel(other.into())),
        }
        match &self.bind {
            BindMode::Direct {
                user_dn_template, ..
            } => {
                if user_dn_template.trim().is_empty() {
                    return Err(ConfigError::Empty {
                        field: "bind.user_dn_template",
                    });
                }
                if !user_dn_template.contains(USERNAME_PLACEHOLDER) {
                    return Err(ConfigError::MissingUsernamePlaceholder {
                        field: "bind.user_dn_template",
                        placeholder: USERNAME_PLACEHOLDER,
                    });
                }
            }
            BindMode::Search {
                bind_dn,
                base_dn,
                user_filter,
                ..
            } => {
                if bind_dn.trim().is_empty() {
                    return Err(ConfigError::Empty {
                        field: "bind.bind_dn",
                    });
                }
                if base_dn.trim().is_empty() {
                    return Err(ConfigError::Empty {
                        field: "bind.base_dn",
                    });
                }
                if user_filter.trim().is_empty() {
                    return Err(ConfigError::Empty {
                        field: "bind.user_filter",
                    });
                }
                if !user_filter.contains(USERNAME_PLACEHOLDER) {
                    return Err(ConfigError::MissingUsernamePlaceholder {
                        field: "bind.user_filter",
                        placeholder: USERNAME_PLACEHOLDER,
                    });
                }
            }
        }
        Ok(())
    }

    /// The directory attributes to request when reading the caller's entry:
    /// the group attribute, the optional subject attribute, and any extra
    /// projected attributes — deduplicated case-insensitively (LDAP
    /// attribute names are case-insensitive).
    pub fn read_attributes(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut push = |name: &str| {
            if !name.is_empty() && !out.iter().any(|e| e.eq_ignore_ascii_case(name)) {
                out.push(name.to_owned());
            }
        };
        push(&self.group_attribute);
        if let Some(sa) = &self.subject_attribute {
            push(sa);
        }
        for a in &self.attributes {
            push(a);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn direct_cfg() -> serde_json::Value {
        json!({
            "url": "ldaps://dc.example.com:636",
            "bind": {
                "mode": "direct",
                "user_dn_template": "uid={username},ou=people,dc=example,dc=org"
            }
        })
    }

    #[test]
    fn parses_direct_with_defaults() {
        let cfg = LdapIdentityConfig::parse(&direct_cfg().to_string()).unwrap();
        assert_eq!(cfg.group_attribute, "memberOf");
        assert!(cfg.roles_from_group_cn);
        assert_eq!(cfg.timeout_ms, 10_000);
        assert_eq!(cfg.size_limit, 100);
        assert_eq!(cfg.resolution.trust_level, "verified");
        assert_eq!(cfg.resolution.auth_provider_label, "ldap");
        assert!(matches!(cfg.bind, BindMode::Direct { .. }));
    }

    #[test]
    fn parses_search_mode() {
        let cfg = json!({
            "url": "ldap://dc.example.com:389",
            "bind": {
                "mode": "search",
                "bind_dn": "cn=svc,dc=example,dc=org",
                "bind_password": "secret",
                "base_dn": "ou=people,dc=example,dc=org",
                "user_filter": "(sAMAccountName={username})"
            },
            "subject_attribute": "sAMAccountName",
            "attributes": ["mail", "displayName"]
        });
        let cfg = LdapIdentityConfig::parse(&cfg.to_string()).unwrap();
        assert!(matches!(cfg.bind, BindMode::Search { .. }));
        // read_attributes = group + subject + extras, deduped.
        let attrs = cfg.read_attributes();
        assert_eq!(
            attrs,
            vec!["memberOf", "sAMAccountName", "mail", "displayName"]
        );
    }

    #[test]
    fn rejects_non_ldap_url() {
        let mut c = direct_cfg();
        c["url"] = json!("https://dc/");
        let err = LdapIdentityConfig::parse(&c.to_string()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidUrl(_)));
    }

    #[test]
    fn rejects_template_without_placeholder() {
        let mut c = direct_cfg();
        c["bind"]["user_dn_template"] = json!("uid=fixed,ou=people,dc=example,dc=org");
        let err = LdapIdentityConfig::parse(&c.to_string()).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::MissingUsernamePlaceholder { .. }
        ));
    }

    #[test]
    fn rejects_filter_without_placeholder() {
        let cfg = json!({
            "url": "ldap://dc:389",
            "bind": {
                "mode": "search",
                "bind_dn": "cn=svc,dc=x",
                "bind_password": "p",
                "base_dn": "dc=x",
                "user_filter": "(objectClass=person)"
            }
        });
        let err = LdapIdentityConfig::parse(&cfg.to_string()).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::MissingUsernamePlaceholder { .. }
        ));
    }

    #[test]
    fn rejects_invalid_trust_level() {
        let mut c = direct_cfg();
        c["resolution"] = json!({ "trust_level": "alien" });
        let err = LdapIdentityConfig::parse(&c.to_string()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidTrustLevel(v) if v == "alien"));
    }

    #[test]
    fn read_attributes_dedups_case_insensitively() {
        let mut c = direct_cfg();
        c["group_attribute"] = json!("memberOf");
        c["subject_attribute"] = json!("memberof"); // same attr, different case
        c["attributes"] = json!(["Mail", "mail"]); // duplicate
        let cfg = LdapIdentityConfig::parse(&c.to_string()).unwrap();
        // memberof folds into memberOf; mail appears once.
        assert_eq!(cfg.read_attributes(), vec!["memberOf", "Mail"]);
    }
}
