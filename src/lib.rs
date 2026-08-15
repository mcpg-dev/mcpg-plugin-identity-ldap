//! `dev.mcpg.identity.ldap` — LDAP / Active Directory identity plugin.
//!
//! Resolves caller identity from `Authorization: Basic
//! <b64(username:password)>` by binding to a directory **as the caller** —
//! the directory verifies the password — then projecting the caller's group
//! memberships into roles/groups on the gateway identity context.
//!
//! # Trust model
//!
//! A successful directory simple-bind is cryptographic proof the caller
//! controls the password, so `resolution.trust_level: "verified"` (default)
//! puts a bound caller in the same trust bucket as an OIDC-verified JWT.
//! Operators on weaker contracts downgrade to `"header_asserted"`.
//!
//! # Async-from-sync
//!
//! The cdylib FFI resolve path is synchronous, but an LDAP bind is network
//! I/O. Like the `oidc` sibling, this plugin bundles a private
//! `tokio::runtime::Runtime` and `block_on`s the bind on each *sync*
//! resolve. The async `IdentityProviderPlugin` path awaits directly and
//! never touches the owned runtime.

pub mod config;
mod ldap;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use mcpg_plugin_protocol::{
    IdentityProviderPlugin, IdentityResolution, PluginClass, PluginIdentity, PluginManifest,
};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncIdentityResolver;
use serde_json::Value;
use tokio::runtime::Runtime;
use tracing::{info_span, warn};

use config::USERNAME_PLACEHOLDER;
pub use config::{BindMode, ConfigError, LdapIdentityConfig, ResolutionConfig};
use ldap::{BindOutcome, DirectoryUser};

const PLUGIN_ID: &str = "dev.mcpg.identity.ldap";

fn record_resolve_outcome(result: &IdentityResolution, elapsed: Duration) {
    let outcome = match result {
        IdentityResolution::Resolved { .. } => "resolved",
        IdentityResolution::None => "none",
        IdentityResolution::Invalid { .. } => "invalid",
    };
    metrics::counter!(
        "mcpg_identity_ldap_resolutions_total",
        "outcome" => outcome,
    )
    .increment(1);
    metrics::histogram!("mcpg_identity_ldap_resolve_ms").record(elapsed.as_millis() as f64);
    match result {
        IdentityResolution::Resolved { identity } => tracing::debug!(
            subject = identity.subject_id.as_deref().unwrap_or(""),
            roles = identity.roles.len(),
            elapsed_ms = %elapsed.as_millis(),
            "ldap identity resolved"
        ),
        IdentityResolution::None => tracing::debug!(
            elapsed_ms = %elapsed.as_millis(),
            "ldap identity: no Basic credential — fall through"
        ),
        IdentityResolution::Invalid { reason } => warn!(
            reason = %reason,
            elapsed_ms = %elapsed.as_millis(),
            "ldap identity: rejected"
        ),
    }
}

// ----------------------------------------------------------- header parsing

/// Parsed `Authorization: Basic` credential.
enum ParsedBasic {
    /// No credential, or a non-Basic scheme — fall through to other
    /// resolvers.
    None,
    /// A Basic credential that is malformed (bad base64 / no colon / empty
    /// field). Rejected — never attempted against the directory (an empty
    /// password would otherwise become an unauthenticated bind).
    Invalid(String),
    /// A well-formed username + password.
    Credentials { username: String, password: String },
}

fn lookup_header<'a>(headers: &'a [(String, String)], target: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case(target).then_some(value.as_str()))
}

fn strip_basic_prefix(value: &str) -> Option<&str> {
    // Case-insensitive scheme match per RFC 7235.
    let scheme: String = value.chars().take(5).collect();
    if scheme.len() != 5 || !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    value[5..].strip_prefix(' ')
}

fn parse_basic(headers: &[(String, String)]) -> ParsedBasic {
    let Some(auth_value) = lookup_header(headers, "authorization") else {
        return ParsedBasic::None;
    };
    let Some(credential) = strip_basic_prefix(auth_value) else {
        return ParsedBasic::None;
    };
    if credential.is_empty() {
        return ParsedBasic::None;
    }
    let decoded = match BASE64_STANDARD.decode(credential.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => {
            return ParsedBasic::Invalid("malformed Basic credential (base64)".into());
        }
    };
    let decoded_str = match std::str::from_utf8(&decoded) {
        Ok(s) => s,
        Err(_) => {
            return ParsedBasic::Invalid("malformed Basic credential (non-utf8)".into());
        }
    };
    let Some(colon_idx) = decoded_str.find(':') else {
        return ParsedBasic::Invalid("malformed Basic credential (no colon)".into());
    };
    let username = &decoded_str[..colon_idx];
    let password = &decoded_str[colon_idx + 1..];
    if username.is_empty() {
        return ParsedBasic::Invalid("empty username".into());
    }
    // An empty password must never reach the directory: many servers treat a
    // simple-bind with an empty password as an anonymous/unauthenticated bind
    // that *succeeds*. Reject up front.
    if password.is_empty() {
        return ParsedBasic::Invalid("empty password".into());
    }
    ParsedBasic::Credentials {
        username: username.to_owned(),
        password: password.to_owned(),
    }
}

// ------------------------------------------------------------------ plugin

pub struct LdapIdentityPlugin {
    inner: Arc<Inner>,
    /// Private current-thread runtime for the sync FFI resolve path. Mirrors
    /// the oidc identity plugin; lives until the plugin is dropped.
    runtime: Runtime,
}

struct Inner {
    manifest: PluginManifest,
    cfg: LdapIdentityConfig,
    timeout: Duration,
    read_attrs: Vec<String>,
}

impl LdapIdentityPlugin {
    /// SDK macro factory: parse operator config JSON. On parse failure the
    /// plugin refuses to load — a silently-misconfigured identity resolver is
    /// a security hole, not a harmless default (same stance as oidc + basic).
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = LdapIdentityConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "ldap identity: config parse failed; refusing to register"
            );
            panic!(
                "ldap identity config parse failed: {err}. A misconfigured \
                 identity resolver is a security hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg)
    }

    fn from_validated_config(cfg: LdapIdentityConfig) -> Self {
        let timeout = Duration::from_millis(cfg.timeout_ms);
        let read_attrs = cfg.read_attributes();
        let mode = match &cfg.bind {
            BindMode::Direct { .. } => "direct",
            BindMode::Search { .. } => "search",
        };
        tracing::info!(
            plugin_id = PLUGIN_ID,
            mode,
            url = %cfg.url,
            "ldap identity: configured"
        );
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "LDAP / Active Directory Identity Resolver".into(),
                    plugin_class: PluginClass::IdentityProvider,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                cfg,
                timeout,
                read_attrs,
            }),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .thread_name("mcpg-ldap-identity-runtime")
                .build()
                .expect("build ldap identity tokio runtime"),
        }
    }

    /// Verify the caller against the directory and read their entry. Async
    /// core shared by both trait impls.
    pub async fn authenticate(&self, username: &str, password: &str) -> BindOutcome {
        let inner = &self.inner;
        match &inner.cfg.bind {
            BindMode::Direct {
                user_dn_template,
                groups_base_dn,
            } => {
                // {username} goes into a DN → RFC 4514 DN-escape.
                let escaped = ldap3::dn_escape(username);
                let user_dn = user_dn_template.replace(USERNAME_PLACEHOLDER, escaped.as_ref());
                ldap::resolve_direct(
                    &inner.cfg.url,
                    &user_dn,
                    password,
                    groups_base_dn.as_deref(),
                    &inner.read_attrs,
                    inner.timeout,
                )
                .await
            }
            BindMode::Search {
                bind_dn,
                bind_password,
                base_dn,
                user_filter,
            } => {
                // {username} goes into a filter → RFC 4515 filter-escape.
                let escaped = ldap3::ldap_escape(username);
                let filter = user_filter.replace(USERNAME_PLACEHOLDER, escaped.as_ref());
                ldap::resolve_search(
                    &inner.cfg.url,
                    bind_dn,
                    bind_password,
                    base_dn,
                    &filter,
                    password,
                    &inner.read_attrs,
                    inner.timeout,
                )
                .await
            }
        }
    }

    /// Map a bind outcome to a resolution. `BadCredentials` and
    /// `UserNotFound` collapse to one generic message — the resolver does not
    /// leak whether a username exists.
    fn map_outcome(&self, outcome: BindOutcome) -> IdentityResolution {
        match outcome {
            BindOutcome::Authenticated(user) => IdentityResolution::Resolved {
                identity: self.build_identity(user),
            },
            BindOutcome::BadCredentials | BindOutcome::UserNotFound => {
                IdentityResolution::Invalid {
                    reason: "invalid username or password".into(),
                }
            }
            BindOutcome::Ambiguous => IdentityResolution::Invalid {
                reason: "ambiguous directory match for user".into(),
            },
            BindOutcome::Unavailable(detail) => {
                // Fail closed: an unverifiable credential is rejected, not
                // passed through. Detail stays in logs, not the caller's
                // reason.
                warn!(detail = %detail, "ldap identity: directory unavailable; failing closed");
                IdentityResolution::Invalid {
                    reason: "directory unavailable".into(),
                }
            }
        }
    }

    /// Project a bound directory entry into a `PluginIdentity`.
    fn build_identity(&self, user: DirectoryUser) -> PluginIdentity {
        let inner = &self.inner;
        let res = &inner.cfg.resolution;

        // groups: full DNs from the group attribute (case-insensitive key).
        let mut groups: Vec<String> = user
            .attrs
            .get(&inner.cfg.group_attribute.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default();
        groups.truncate(inner.cfg.size_limit);

        // roles: friendly CN of each group DN (optional).
        let roles: Vec<String> = if inner.cfg.roles_from_group_cn {
            groups
                .iter()
                .filter_map(|dn| ldap::group_dn_to_role(dn))
                .collect()
        } else {
            Vec::new()
        };

        // subject: a configured attribute's first value, else the bound DN.
        let subject_id = inner
            .cfg
            .subject_attribute
            .as_ref()
            .and_then(|sa| user.attrs.get(&sa.to_ascii_lowercase()))
            .and_then(|vals| vals.first())
            .cloned()
            .unwrap_or_else(|| user.dn.clone());

        // projected attributes: first value of each requested extra attr,
        // keyed by the operator's requested name.
        let mut attributes = BTreeMap::new();
        for name in &inner.cfg.attributes {
            if let Some(v) = user
                .attrs
                .get(&name.to_ascii_lowercase())
                .and_then(|vals| vals.first())
            {
                attributes.insert(name.clone(), v.clone());
            }
        }

        PluginIdentity {
            kind: res.trust_level.clone(),
            trust_level: res.trust_level.clone(),
            subject_id: Some(subject_id),
            auth_provider: Some(res.auth_provider_label.clone()),
            issuer: Some(inner.cfg.url.clone()),
            roles,
            groups,
            scopes: Vec::new(),
            attributes,
        }
    }
}

impl std::fmt::Debug for LdapIdentityPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapIdentityPlugin")
            .field("id", &self.inner.manifest.id)
            .field("url", &self.inner.cfg.url)
            .finish()
    }
}

#[async_trait]
impl IdentityProviderPlugin for LdapIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        use tracing::Instrument;
        let span = info_span!("identity_ldap_resolve", plugin_id = PLUGIN_ID);
        async move {
            let started = Instant::now();
            let result = match parse_basic(headers) {
                ParsedBasic::None => IdentityResolution::None,
                ParsedBasic::Invalid(reason) => IdentityResolution::Invalid { reason },
                ParsedBasic::Credentials { username, password } => {
                    let outcome = self.authenticate(&username, &password).await;
                    self.map_outcome(outcome)
                }
            };
            record_resolve_outcome(&result, started.elapsed());
            result
        }
        .instrument(span)
        .await
    }
}

impl SyncIdentityResolver for LdapIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        let _span = info_span!("identity_ldap_resolve", plugin_id = PLUGIN_ID).entered();
        let started = Instant::now();
        // Parse first; only spin the runtime when a credential is actually
        // present (the no-credential fast path never blocks).
        let result = match parse_basic(headers) {
            ParsedBasic::None => IdentityResolution::None,
            ParsedBasic::Invalid(reason) => IdentityResolution::Invalid { reason },
            ParsedBasic::Credentials { username, password } => {
                let outcome = self
                    .runtime
                    .block_on(self.authenticate(&username, &password));
                self.map_outcome(outcome)
            }
        };
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

declare_plugin! {

    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        identity as id {
            inner_name: "",
            plugin_type: LdapIdentityPlugin,
            // No cluster-coordinated state: the directory is the source of
            // truth, queried live per resolve.
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> LdapIdentityPlugin {
                LdapIdentityPlugin::from_config_json(cfg)
            },
        }
    ],
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn direct_plugin() -> LdapIdentityPlugin {
        LdapIdentityPlugin::from_config_json(
            &json!({
                "url": "ldap://127.0.0.1:1",
                "bind": {
                    "mode": "direct",
                    "user_dn_template": "uid={username},ou=people,dc=example,dc=org"
                },
                "subject_attribute": "uid",
                "attributes": ["mail"],
                "timeout_ms": 300
            })
            .to_string(),
        )
    }

    fn basic_header(creds: &str) -> Vec<(String, String)> {
        let encoded = BASE64_STANDARD.encode(creds.as_bytes());
        vec![("Authorization".into(), format!("Basic {encoded}"))]
    }

    // -- header parsing -----------------------------------------------------

    #[test]
    fn no_authorization_header_is_none() {
        assert!(matches!(parse_basic(&[]), ParsedBasic::None));
    }

    #[test]
    fn bearer_scheme_is_none() {
        let h = vec![("Authorization".into(), "Bearer xyz".into())];
        assert!(matches!(parse_basic(&h), ParsedBasic::None));
    }

    #[test]
    fn malformed_base64_is_invalid() {
        let h = vec![("Authorization".into(), "Basic !!nope!!".into())];
        match parse_basic(&h) {
            ParsedBasic::Invalid(r) => assert!(r.contains("base64")),
            other => panic!("unexpected: {}", matches!(other, ParsedBasic::None)),
        }
    }

    #[test]
    fn no_colon_is_invalid() {
        match parse_basic(&basic_header("alicenocolon")) {
            ParsedBasic::Invalid(r) => assert!(r.contains("no colon")),
            _ => panic!("expected invalid"),
        }
    }

    #[test]
    fn empty_password_is_invalid_not_attempted() {
        // The anti-anonymous-bind guard: "alice:" must never reach the
        // directory.
        match parse_basic(&basic_header("alice:")) {
            ParsedBasic::Invalid(r) => assert_eq!(r, "empty password"),
            _ => panic!("expected invalid"),
        }
    }

    #[test]
    fn empty_username_is_invalid() {
        match parse_basic(&basic_header(":secret")) {
            ParsedBasic::Invalid(r) => assert_eq!(r, "empty username"),
            _ => panic!("expected invalid"),
        }
    }

    #[test]
    fn well_formed_credential_parses() {
        match parse_basic(&basic_header("alice:hunter2")) {
            ParsedBasic::Credentials { username, password } => {
                assert_eq!(username, "alice");
                assert_eq!(password, "hunter2");
            }
            _ => panic!("expected credentials"),
        }
    }

    #[test]
    fn password_may_contain_colons() {
        match parse_basic(&basic_header("alice:a:b:c")) {
            ParsedBasic::Credentials { username, password } => {
                assert_eq!(username, "alice");
                assert_eq!(password, "a:b:c");
            }
            _ => panic!("expected credentials"),
        }
    }

    // -- identity projection ------------------------------------------------

    #[test]
    fn build_identity_maps_groups_roles_subject_attrs() {
        let plugin = direct_plugin();
        let mut attrs = ldap::AttrMap::new();
        attrs.insert(
            "memberof".into(),
            vec![
                "cn=admins,ou=groups,dc=example,dc=org".into(),
                "cn=developers,ou=groups,dc=example,dc=org".into(),
            ],
        );
        attrs.insert("uid".into(), vec!["alice".into()]);
        attrs.insert("mail".into(), vec!["alice@example.org".into()]);
        let user = DirectoryUser {
            dn: "uid=alice,ou=people,dc=example,dc=org".into(),
            attrs,
        };
        let id = plugin.build_identity(user);
        assert_eq!(id.subject_id.as_deref(), Some("alice")); // from uid attr
        assert_eq!(id.trust_level, "verified");
        assert_eq!(id.auth_provider.as_deref(), Some("ldap"));
        assert_eq!(
            id.groups,
            vec![
                "cn=admins,ou=groups,dc=example,dc=org".to_owned(),
                "cn=developers,ou=groups,dc=example,dc=org".to_owned()
            ]
        );
        assert_eq!(id.roles, vec!["admins".to_owned(), "developers".to_owned()]);
        assert_eq!(
            id.attributes.get("mail").map(String::as_str),
            Some("alice@example.org")
        );
    }

    #[test]
    fn build_identity_falls_back_to_dn_subject() {
        // subject_attribute "uid" absent from the entry → subject is the DN.
        let plugin = direct_plugin();
        let user = DirectoryUser {
            dn: "uid=bob,ou=people,dc=example,dc=org".into(),
            attrs: ldap::AttrMap::new(),
        };
        let id = plugin.build_identity(user);
        assert_eq!(
            id.subject_id.as_deref(),
            Some("uid=bob,ou=people,dc=example,dc=org")
        );
        assert!(id.roles.is_empty());
        assert!(id.groups.is_empty());
    }

    // -- manifest + sync runtime path --------------------------------------

    #[test]
    fn manifest_is_identity_provider() {
        let plugin = direct_plugin();
        let m = SyncIdentityResolver::manifest(&plugin);
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.plugin_class, PluginClass::IdentityProvider);
    }

    #[test]
    fn sync_no_credential_returns_none_without_blocking() {
        let plugin = direct_plugin();
        let meta = mcpg_plugin_protocol::types::RequestMetadata::default();
        let r = SyncIdentityResolver::resolve_identity(&plugin, &[], &meta, &json!({}));
        assert!(matches!(r, IdentityResolution::None));
    }

    #[test]
    fn sync_unreachable_directory_fails_closed() {
        // url points at a closed port; the bind fails fast (refused) or hits
        // the 300 ms timeout → Unavailable → Invalid "directory unavailable".
        let plugin = direct_plugin();
        let meta = mcpg_plugin_protocol::types::RequestMetadata::default();
        let r = SyncIdentityResolver::resolve_identity(
            &plugin,
            &basic_header("alice:hunter2"),
            &meta,
            &json!({}),
        );
        match r {
            IdentityResolution::Invalid { reason } => assert_eq!(reason, "directory unavailable"),
            other => panic!("expected Invalid(directory unavailable), got {other:?}"),
        }
    }

    #[test]
    fn sync_empty_password_rejected_without_blocking() {
        let plugin = direct_plugin();
        let meta = mcpg_plugin_protocol::types::RequestMetadata::default();
        let r = SyncIdentityResolver::resolve_identity(
            &plugin,
            &basic_header("alice:"),
            &meta,
            &json!({}),
        );
        assert!(matches!(r, IdentityResolution::Invalid { .. }));
    }
}
