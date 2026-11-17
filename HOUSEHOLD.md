# Directory-owned household identities

This fork adds opt-in canonical LDAP identities to OIDC and ForwardAuth. It
does not link by matching email addresses or usernames across providers.

Define protected, visible, non-editable LLDAP attributes:

- `auth-person-id`: one immutable ID, declared in configuration and never reused.
- `auth-identities`: a list of JSON `[issuer, subject]` pairs. An authenticated
  OAuth subject must have exactly one explicit directory binding.

All emitted profile fields and groups come from the resolved LDAP person.
SSO sessions pin that person's ID at credential authentication; reassigning a
username or binding requires fresh authentication. Refresh and userinfo
revalidate bindings and app grants against the current directory. Missing,
ambiguous or malformed bindings and directory failures deny access.

```yaml
database:
  driver: memory
household:
  enabled: true
  personAttribute: auth-person-id
  identityAttribute: auth-identities
  providerIssuers:
    google: https://accounts.google.com
  clientGroups:
    immich: [household]
  proxyGroups:
    whoami.example.com: [household]
```

`clientGroups` maps actual OIDC client IDs to accepted directory groups.
`proxyGroups` maps exact lowercase ForwardAuth hostnames to accepted groups.
At least one required group must match. Unlisted clients/hosts deny access.
Household mode disables unauthenticated IP/path bypasses for ForwardAuth;
canonical directory grants govern its authenticated responses. ForwardAuth
returns canonical `Remote-User`, `Remote-Name`, `Remote-Email`, `Remote-Groups`
and `Remote-Sub` (the person ID). OIDC retains a pairwise subject per client.
Do not repoint an existing OAuth provider ID to a different upstream issuer.

The in-memory SSO pin cache is bounded; expiry/eviction or restart requires
reauthentication. Use one replica with the memory backend. Persist signing
keys separately. LLDAP owns normal directory persistence; Tinyauth needs no
identity database. Existing application sessions remain under each app's
control and are not remotely destroyed by these checks.

Use a read-only directory service account. The canary isolates plaintext LDAP
within its namespace; a shared production directory should use verified LDAP
TLS. The resolver makes bounded fresh directory reads and currently scans the
small directory rather than maintaining an additional identity store.

Run `tests/household/check.sh` for real LLDAP + synthetic upstream OAuth + OIDC
and ForwardAuth integration checks. All fixture credentials are test-only.
This does not prove genuine Google enrollment or an existing Immich migration.

Upstream already publishes release/nightly images. `Biosnet image` adds a
branch-push build for this fork, runs backend and integration checks, and
publishes an amd64 image tagged by full commit SHA to GHCR. Talos pins its digest.
Changes here were developed with Codex; no upstream contribution was submitted.
