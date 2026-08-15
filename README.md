# `mcpg-plugin-identity-ldap`

LDAP / Active Directory **identity** plugin for mcpg
(`class: identity_provider`, `id: dev.mcpg.identity.ldap`). Resolves the
caller's identity from an `Authorization: Basic` header by binding to a
directory **as the caller** — the directory itself verifies the password —
then projects the caller's group memberships into roles/groups on the
gateway identity context.

Part of the legacy → MCP bridge suite. The
authentication counterpart to the `dev.mcpg.backend.ldap` **backend** plugin
(which binds a *service account* to search the directory as a tool/resource).

## How it works

Per resolve, given `Authorization: Basic <b64(username:password)>`:

1. The header is parsed into `username` + `password`. An empty username or
   password is rejected up front — an empty-password simple-bind is an
   anonymous bind that many servers *accept*, so it must never reach the
   directory.
2. The caller's password is verified against the directory by one of two
   **bind modes** (below). A successful bind is cryptographic proof the
   caller controls the password.
3. The caller's entry is read for the group attribute (`memberOf` by
   default) and any projected attributes; group DNs become `groups`, their
   CNs become `roles`.
4. Resolution: `Resolved` (bound, with roles/groups), `Invalid` (bad
   credential / unknown user / directory unavailable — fail closed), or
   `None` (no Basic header — fall through to the next resolver).

The cdylib FFI resolve path is synchronous; the LDAP bind is async network
I/O. Like the `oidc` sibling, the plugin bundles a private
`tokio::runtime::Runtime` and `block_on`s the bind.

### Bind modes

| Mode | How the password is verified | Use when |
|---|---|---|
| `direct` | Template the caller's DN (`uid={username},…`), then simple-bind it with the caller's password. | DNs are predictable (fixed `ou`, known RDN attribute). |
| `search` | Bind a **service account**, search for the caller by filter, then re-bind as the matched DN with the caller's password. | DNs aren't predictable — the **Active Directory** case (`sAMAccountName` → DN). |

`{username}` is escaped per its context before substitution: **RFC 4514
DN-escaping** in `user_dn_template` (a comma can't inject a DN component),
**RFC 4515 filter-escaping** in `user_filter` (a `*` can't become a
wildcard).

## Configuration

| Field | Type | Default | Notes |
|---|---|---|---|
| `url` | string (required) | — | `ldap://host:389` or `ldaps://host:636`. |
| `bind` | object (required) | — | The bind mode — see below. |
| `group_attribute` | string | `memberOf` | Attribute holding group-membership DNs. |
| `roles_from_group_cn` | bool | `true` | Map each group DN's CN into `roles` (`cn=admins,…` → `admins`). |
| `subject_attribute` | string | — | Directory attribute to use as `subject_id`. Default: the bound DN. |
| `attributes` | `[string]` | `[]` | Extra attributes copied onto the identity (first value each). |
| `size_limit` | int | `100` | Cap on group/role values projected. |
| `timeout_ms` | int | `10000` | connect + bind + search timeout. |
| `resolution.trust_level` | `verified`\|`header_asserted` | `verified` | Trust bucket for a bound caller. |
| `resolution.auth_provider_label` | string | `ldap` | `auth_provider` on the identity. |

**`direct` mode** — `bind: { mode: "direct", … }`:

| Field | Type | Default | Notes |
|---|---|---|---|
| `user_dn_template` | string (required) | — | Must contain `{username}`. e.g. `uid={username},ou=people,dc=corp,dc=com`. |
| `groups_base_dn` | string | the bound DN | Where to read group memberships. |

**`search` mode** — `bind: { mode: "search", … }`:

| Field | Type | Default | Notes |
|---|---|---|---|
| `bind_dn` | string (required) | — | Service-account bind DN. |
| `bind_password` | string (required) | — | Resolved by the gateway secret-resolver (`${env.X}` / `vault://…` / `file://…`) — never plaintext in committed config. |
| `base_dn` | string (required) | — | Search base for the user lookup. |
| `user_filter` | string (required) | — | Must contain `{username}`. e.g. `(sAMAccountName={username})`. |

### As an identity resolver

```yaml
plugins:
  - id: dev.mcpg.identity.ldap
    class: identity_provider
    source: { oci: "{{OCI_BASE}}/identity-ldap:<ver>" }
    config:
      # Active Directory: search-then-bind on sAMAccountName.
      url: "ldaps://dc1.corp.example.com:636"
      bind:
        mode: search
        bind_dn: "cn=svc-mcpg,ou=svc,dc=corp,dc=example,dc=com"
        bind_password: "${env.LDAP_SVC_PASSWORD}"
        base_dn: "ou=people,dc=corp,dc=example,dc=com"
        user_filter: "(sAMAccountName={username})"
      subject_attribute: sAMAccountName
      group_attribute: memberOf
      attributes: [mail, displayName, department]
```

```yaml
      # Simpler directory: direct bind on a predictable DN.
      url: "ldaps://ldap.example.com:636"
      bind:
        mode: direct
        user_dn_template: "uid={username},ou=people,dc=example,dc=org"
```

The resolved identity flows into the gateway identity context: downstream
tool-gates, policy plugins, and audit see the caller's `subject_id`,
`roles`, `groups`, and `attributes` — e.g. a Casbin/Cedar policy can gate a
tool on `g(memberOf, "cn=admins,…")` or on a mapped `admins` role.

## Resolved identity

| Field | From |
|---|---|
| `subject_id` | `subject_attribute`'s first value, else the bound DN. |
| `trust_level` / `kind` | `resolution.trust_level` (`verified`). |
| `auth_provider` | `resolution.auth_provider_label` (`ldap`). |
| `issuer` | the directory `url`. |
| `groups` | full DNs from `group_attribute`. |
| `roles` | CN of each group DN (when `roles_from_group_cn`). |
| `attributes` | first value of each requested extra attribute. |

## Security

- **Bind-as-caller.** The directory is the password oracle — the plugin
  never sees or stores a password hash; it proves possession by binding.
  The caller's password is used only for the bind and is never logged.
- **No plaintext secrets.** The service-account `bind_password` (search
  mode) is resolved by the gateway secret-resolver; it is never committed.
- **Injection defense.** `{username}` is RFC-4514 DN-escaped into DN
  templates and RFC-4515 filter-escaped into search filters.
- **No anonymous bind.** Empty username/password are rejected before any
  bind (an empty-password bind is an anonymous bind on many servers).
- **No user enumeration.** A wrong password and an unknown user both return
  the same generic `invalid username or password`.
- **Fail closed.** A directory that is unreachable / times out yields
  `Invalid` (the request is rejected), never a silent pass-through.
- **TLS.** LDAPS over rustls. Note: `ldap3` 0.11's only rustls path is the
  legacy `rustls 0.21` / `rustls-webpki 0.101` stack (native-tls is banned),
  so LDAPS reintroduces that transitive stack — covered by scoped
  `deny.toml` ignores (RUSTSEC-2026-0098/-0099/-0104). Revisit when ldap3
  ships on rustls 0.23.

## Build / test

```bash
nx build mcpg-plugin-identity-ldap
nx test  mcpg-plugin-identity-ldap                                    # unit tests
cargo test -p mcpg-plugin-identity-ldap --features integration-tests   # OpenLDAP (docker)
nx lint  mcpg-plugin-identity-ldap
```

## Scope / deferred

- **`memberOf` overlay.** Group → role mapping reads `memberOf`. On
  directories without the memberof overlay (so without that attribute),
  configure `group_attribute` to a populated one, or add the overlay
  upstream. Reverse-group-search (find groups where the user is a `member`)
  is a possible follow-on.
- **StartTLS on `ldap://`** — v1 is `ldap://` (plaintext) or `ldaps://`
  (implicit TLS); StartTLS upgrade is a follow-on.
- **Connection pooling** — v1 connects + binds per resolve (bind-as-caller
  is inherently per-request); add caching for hot paths if needed.
- **Native modern-rustls LDAPS** — pending an ldap3 upstream release.
