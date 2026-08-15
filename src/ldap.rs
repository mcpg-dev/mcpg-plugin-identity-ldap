//! LDAP bind-as-caller machinery: connect, verify the caller's password by
//! binding *as them*, and read back the entry (group memberships +
//! projected attributes).
//!
//! The directory is the password oracle — a successful simple-bind with the
//! caller's password is the proof of identity. Two strategies share this
//! module: [`resolve_direct`] (template the DN) and [`resolve_search`]
//! (service-account search, then re-bind as the matched DN).

use std::collections::HashMap;
use std::time::Duration;

use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

/// Attribute view read back from the caller's directory entry. Keys are
/// lower-cased (LDAP attribute names are case-insensitive); values stay
/// arrays (LDAP attributes are multi-valued).
pub type AttrMap = HashMap<String, Vec<String>>;

/// The caller's directory entry after a successful authenticating bind.
#[derive(Debug, Clone)]
pub struct DirectoryUser {
    /// The bound (authenticated) DN.
    pub dn: String,
    /// Lower-cased attribute map read from the entry.
    pub attrs: AttrMap,
}

/// Outcome of an authentication attempt. The mapping to `IdentityResolution`
/// lives in `lib.rs`; `BadCredentials` and `UserNotFound` are intentionally
/// surfaced to the caller as one generic message there (no user enumeration).
#[derive(Debug)]
pub enum BindOutcome {
    /// Password verified against the directory; entry read.
    Authenticated(DirectoryUser),
    /// The directory rejected the caller's bind (wrong password).
    BadCredentials,
    /// Search mode: the user filter matched no entries.
    UserNotFound,
    /// Search mode: the user filter matched more than one entry.
    Ambiguous,
    /// Connect / timeout / service-account / transport failure. The resolver
    /// fails closed on this (the credential could not be verified).
    Unavailable(String),
}

/// Result of one simple-bind attempt, separating an authentication rejection
/// (non-zero LDAP result code) from a transport failure.
enum BindAttempt {
    Ok,
    Rejected,
    Transport(String),
}

/// Open a connection and start its driver. The returned [`Ldap`] handle is
/// used for binds/searches; the driver task lives until the handle drops.
async fn connect(url: &str, timeout: Duration) -> Result<Ldap, String> {
    let settings = LdapConnSettings::new().set_conn_timeout(timeout);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, url)
        .await
        .map_err(|e| format!("connect failed: {e}"))?;
    ldap3::drive!(conn);
    ldap.with_timeout(timeout);
    Ok(ldap)
}

/// Simple-bind `dn` with `password`. A non-zero result code is an
/// authentication rejection; an `Err` is a transport failure.
async fn try_bind(ldap: &mut Ldap, dn: &str, password: &str, timeout: Duration) -> BindAttempt {
    ldap.with_timeout(timeout);
    match ldap.simple_bind(dn, password).await {
        Ok(res) if res.rc == 0 => BindAttempt::Ok,
        Ok(_) => BindAttempt::Rejected,
        Err(e) => BindAttempt::Transport(format!("{e}")),
    }
}

/// Read the caller's own entry (base-scoped) for the requested attributes.
/// Fail-soft: a read failure yields an empty map — authentication is already
/// proven by the bind, so a missing/unreadable `memberOf` must not deny
/// access, only omit roles.
async fn read_entry(ldap: &mut Ldap, base: &str, attrs: &[String], timeout: Duration) -> AttrMap {
    ldap.with_timeout(timeout);
    let attr_refs: Vec<&str> = attrs.iter().map(String::as_str).collect();
    match ldap
        .search(base, Scope::Base, "(objectClass=*)", attr_refs)
        .await
    {
        Ok(sr) => match sr.success() {
            Ok((entries, _res)) => entries
                .into_iter()
                .next()
                .map(|re| lower_attrs(SearchEntry::construct(re)))
                .unwrap_or_default(),
            Err(e) => {
                tracing::debug!(error = %e, base = %base, "ldap identity: entry read rejected");
                AttrMap::new()
            }
        },
        Err(e) => {
            tracing::debug!(error = %e, base = %base, "ldap identity: entry read failed");
            AttrMap::new()
        }
    }
}

/// One found user from a service-account search.
enum FindUser {
    Found(DirectoryUser),
    NotFound,
    Ambiguous,
    Error(String),
}

/// Search `base` (subtree) for `filter`, expecting exactly one entry.
async fn search_one(
    ldap: &mut Ldap,
    base: &str,
    filter: &str,
    attrs: &[String],
    timeout: Duration,
) -> FindUser {
    ldap.with_timeout(timeout);
    let attr_refs: Vec<&str> = attrs.iter().map(String::as_str).collect();
    let sr = match ldap.search(base, Scope::Subtree, filter, attr_refs).await {
        Ok(sr) => sr,
        Err(e) => return FindUser::Error(format!("user search failed: {e}")),
    };
    let (entries, _res) = match sr.success() {
        Ok(x) => x,
        Err(e) => return FindUser::Error(format!("user search rejected: {e}")),
    };
    let mut iter = entries.into_iter();
    let Some(first) = iter.next() else {
        return FindUser::NotFound;
    };
    if iter.next().is_some() {
        return FindUser::Ambiguous;
    }
    let entry = SearchEntry::construct(first);
    FindUser::Found(DirectoryUser {
        dn: entry.dn.clone(),
        attrs: lower_attrs(entry),
    })
}

/// Lower-case the attribute keys of a search entry for case-insensitive
/// lookup; the DN is dropped (callers track it separately).
fn lower_attrs(entry: SearchEntry) -> AttrMap {
    let mut m = AttrMap::with_capacity(entry.attrs.len());
    for (k, v) in entry.attrs {
        m.insert(k.to_ascii_lowercase(), v);
    }
    m
}

/// Direct-bind mode: bind the templated user DN with the caller's password,
/// then read their own entry for groups/attributes.
pub async fn resolve_direct(
    url: &str,
    user_dn: &str,
    password: &str,
    groups_base_dn: Option<&str>,
    read_attrs: &[String],
    timeout: Duration,
) -> BindOutcome {
    let mut ldap = match connect(url, timeout).await {
        Ok(l) => l,
        Err(e) => return BindOutcome::Unavailable(e),
    };
    match try_bind(&mut ldap, user_dn, password, timeout).await {
        BindAttempt::Ok => {}
        BindAttempt::Rejected => return BindOutcome::BadCredentials,
        BindAttempt::Transport(e) => return BindOutcome::Unavailable(e),
    }
    let base = groups_base_dn.unwrap_or(user_dn);
    let attrs = read_entry(&mut ldap, base, read_attrs, timeout).await;
    let _ = ldap.unbind().await;
    BindOutcome::Authenticated(DirectoryUser {
        dn: user_dn.to_owned(),
        attrs,
    })
}

/// Search-then-bind mode: bind the service account, find the caller, then
/// re-bind (same connection) as the matched DN with the caller's password to
/// verify it. Attributes come from the service-account search.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_search(
    url: &str,
    bind_dn: &str,
    bind_password: &str,
    base_dn: &str,
    user_filter: &str,
    password: &str,
    read_attrs: &[String],
    timeout: Duration,
) -> BindOutcome {
    let mut ldap = match connect(url, timeout).await {
        Ok(l) => l,
        Err(e) => return BindOutcome::Unavailable(e),
    };
    // Service-account bind. A failure here is an operator problem, not the
    // caller's — fail closed.
    match try_bind(&mut ldap, bind_dn, bind_password, timeout).await {
        BindAttempt::Ok => {}
        BindAttempt::Rejected => {
            return BindOutcome::Unavailable("service-account bind rejected".into());
        }
        BindAttempt::Transport(e) => {
            return BindOutcome::Unavailable(format!("service-account bind: {e}"));
        }
    }
    let found = match search_one(&mut ldap, base_dn, user_filter, read_attrs, timeout).await {
        FindUser::Found(u) => u,
        FindUser::NotFound => return BindOutcome::UserNotFound,
        FindUser::Ambiguous => return BindOutcome::Ambiguous,
        FindUser::Error(e) => return BindOutcome::Unavailable(e),
    };
    // Verify the caller's password by re-binding as the matched DN.
    match try_bind(&mut ldap, &found.dn, password, timeout).await {
        BindAttempt::Ok => {}
        BindAttempt::Rejected => return BindOutcome::BadCredentials,
        BindAttempt::Transport(e) => return BindOutcome::Unavailable(e),
    }
    let _ = ldap.unbind().await;
    BindOutcome::Authenticated(found)
}

/// Extract a group's friendly role name — the value of the first RDN of its
/// DN (`cn=Admins,ou=Groups,dc=x` → `Admins`). Returns `None` for a DN with
/// no parseable leading `attr=value` RDN.
pub fn group_dn_to_role(dn: &str) -> Option<String> {
    let first_rdn = dn.split(',').next()?;
    let eq = first_rdn.find('=')?;
    let value = first_rdn[eq + 1..].trim();
    (!value.is_empty()).then(|| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_from_group_dn() {
        assert_eq!(
            group_dn_to_role("cn=Admins,ou=Groups,dc=example,dc=org").as_deref(),
            Some("Admins")
        );
        assert_eq!(
            group_dn_to_role("CN=Domain Users,CN=Users,DC=corp").as_deref(),
            Some("Domain Users")
        );
    }

    #[test]
    fn role_from_malformed_dn_is_none() {
        assert_eq!(group_dn_to_role(""), None);
        assert_eq!(group_dn_to_role("not-a-dn"), None);
        assert_eq!(group_dn_to_role("cn=,ou=x"), None);
    }
}
