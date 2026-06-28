# dns-acme

## NAME

**dns-acme** — OpenBao DNS-01 ACME certificate issuance plugin with entity-based domain authorization

## DESCRIPTION

**dns-acme** is an OpenBao secrets engine plugin that issues X.509
certificates from any ACME-compatible certificate authority (CA) using the
DNS-01 challenge mechanism.  The motivation behind DNS-ACME is the fact that
most DNS providers only provide API tokens scoped for a whole zone or even 
whole account.  Thus, if you have multiple servers or endpoints in your 
environment that need certificates from an ACME provider, you can't grant 
any of them the ability to enroll as their own name, without also granting
them the ability to enroll as every other name.  DNS-ACME resolves this issue.

The plugin uses an **entity-based authorization model**. An admin provisions
entities and assigns them an `allowed_domains` metadata attribute listing the
domains each entity is authorized to enroll for. During enrollment the plugin
resolves the requesting entity's metadata authoritatively from OpenBao via the
`EntityInfo`.  Every CSR domain must be an exact match against the entity's 
`allowed_domains` list.

The plugin also maps DNS provider credentials to roles by zone. During
enrollment, each CSR domain is matched against configured roles to find the
DNS provider and credentials needed to complete the DNS-01 challenge. The first
role whose zone covers the domain is used.

The plugin maintains its own internal storage for DNS role credentials and
ACME account state. Issuance runs asynchronously: enrollment requests return
immediately with a pending status, and the client polls the retrieve endpoint
until the certificate is issued.

## SYNOPSIS

**bao secrets enable** `-path=<PATH>` `-plugin-name=<NAME>` `plugin`

**bao write** **<PATH>/config/create** `email=`**`<EMAIL>`** `acme_url=`**`<URL>`**

**bao write** **<PATH>/config/roles/**`<NAME>`** `provider=`**`<PROVIDER>`** `zone=`**`<ZONE>`** `...`**`<CREDENTIALS>`**

**bao write** **<PATH>/enroll/new** `csr=`**`<CSR>`**

**bao read** **<PATH>/enroll/retrieve/**`<ID>`**

**bao write** **<PATH>/revoke** `certificate=`**`<CERT>`**

## INSTALLATION

### Enable the Plugin

Register the plugin binary in the OpenBao plugin catalog, then enable it:

```bash
bao plugin register -sha256=<SHA256> dns-acme
bao secrets enable -path=dnsplugin -plugin-name=dns-acme plugin
```

## API PATHS

The following paths are available on the mounted secrets engine:

| Path | Operation | Description |
|---|---|---|
| **<PATH>/config/create** | `bao write` | Create ACME account with generated RSA-2048 key |
| **<PATH>/config** | `bao read`/`bao write` | Read or set ACME account email and key |
| **<PATH>/config/roles** | `bao list`/`bao read` | List configured DNS roles |
| **<PATH>/config/roles/**`<NAME>`** | `bao write`/`bao read`/`bao delete` | Create, read, or delete a DNS role |
| **<PATH>/enroll/new** | `bao write` | Enroll a CSR for certificate issuance |
| **<PATH>/enroll/retrieve/**`<ID>`** | `bao read` | Poll enrollment status and retrieve certificate |
| **<PATH>/enroll/retrieve** | `bao write` | Poll enrollment status (ID in body) |
| **<PATH>/revoke** | `bao write` | Revoke a certificate or cancel a pending enrollment |

## CONFIGURATION PATHS

### config/create

Creates an ACME account with a generated RSA-2048 keypair and registers it
with the ACME CA. The account URI is stored in plugin config and reused
for subsequent operations, including certificate revocation (the URI is sent
as the JWS `kid` header so Let's Encrypt staging accepts the revocation).

| Parameter | Type | Description |
|---|---|---|
| **email** | string | ACME account email address (required; CA may require it) |
| **acme_url** | string | ACME directory URL (defaults to Let's Encrypt production) |

| Output Field | Type | Description |
|---|---|---|
| **email** | string | The registered email |
| **key** | string | The generated private key in PEM format |
| **uri** | string | ACME account URI (e.g. `https://acme-staging-v02.api.letsencrypt.org/acme/acct/12345`) |
| **message** | string | Confirmation string |

```bash
bao write dnsplugin/config/create \
    email=certs@example.com \
    acme_url=https://acme-staging-v02.api.letsencrypt.org/directory
```

### config

Retrieves the current ACME account configuration.

```bash
bao read dnsplugin/config
```

This path also accepts a write/update operation to set the ACME account
credentials directly. When using this form, both `email` and `key` are required.

### config/roles

Lists all configured DNS provider roles.

```bash
bao read dnsplugin/config/roles
```

### config/roles/**`<NAME>`**

Create, update, or delete a DNS provider role. A role maps a DNS provider
name, credential set, and DNS zone to a set of credentials.

| Parameter | Type | Description |
|---|---|---|
| **provider** | string | DNS provider name (e.g. `cloudflare`, `route53`, `gandi`). Any provider supported by go-acme/lego is valid. |
| **zone** | string | DNS zone the API key controls (e.g. `example.com`). Required. The API key must have permissions for this zone and all subdomains. Passed to lego as the `ZONE` and `{PROVIDER}_ZONE` env vars. |
| **`<CREDENTIALS>`** | map | One or more provider-specific credential keys. See [Provider Credential Mapping](#provider-credential-mapping). |

| Output Field | Type | Description |
|---|---|---|
| **message** | string | Confirmation string |
| **name** | string | Role name |
| **provider** | string | DNS provider name |

```bash
bao write dnsplugin/config/roles/cloudflare \
    provider=cloudflare \
    zone=example.com \
    CLOUDFLARE_DNS_API_TOKEN=cfut_mQ40...
```

```bash
bao write dnsplugin/config/roles/route53 \
    provider=route53 \
    zone=staging.example.com \
    AWS_ACCESS_KEY_ID=AKIA... \
    AWS_SECRET_ACCESS_KEY=wJalr...
```

Multiple roles can cover overlapping zones. During enrollment the first matching
role wins — register narrower zones before broader ones to override.

### config/roles/**`<NAME>`**

| Operation | Command | Description |
|---|---|---|
| **Read** | `bao read dnsplugin/config/roles/<NAME>` | Retrieve a role by name |
| **Delete** | `bao delete dnsplugin/config/roles/<NAME>` | Remove a role by name |

## ENROLLMENT PATHS

### enroll/new

Enrolls a CSR for certificate issuance. The CSR is parsed to extract
domain names from its Subject Alternative Name (SAN) extension (or Common Name
fallback). Each domain is then matched against configured role zones — the
first role whose zone covers the domain determines the DNS provider and
credentials. The CSR domains are also validated against the requesting
entity's authoritative `allowed_domains` metadata attribute (see below).

| Parameter | Type | Description |
|---|---|---|
| **csr** | string | CSR in PEM format (auto-decoded if base64-encoded by the CLI) |

| Output Field | Type | Description |
|---|---|---|
| **id** | string | Enrollment identifier (hex string) — present only on success |
| **state** | string | `pending` — DNS-01 challenge is in progress — present only on success |
| **domains** | []string | List of domains from the CSR |
| **message** | string | Human-readable status — present only on success |
| **retrieve_url** | string | URL to poll for completion — present only on success |
| **error** | string | Error message — present when no matching role or entity authorization fails |

#### Entity Authorization

The plugin resolves the entity's metadata authoritatively from OpenBao via the
`EntityInfo` RPC. The entity ID is extracted from the token attached to the
request (`req.EntityID`), and the plugin calls `b.System().EntityInfo(entityID)`
to fetch the entity record, including its `Metadata` map.

**`allowed_domains` is required.** If the entity has no metadata, or the
metadata does not include the `allowed_domains` key, enrollment fails
immediately. There is **no fallback** to role zone matching for authorization.

| Field | Type | Description |
|---|---|---|
| `allowed_domains` | string | Comma-separated list of domain names the entity is authorized to enroll for |

Each CSR domain must be an **exact match** against one entry in `allowed_domains`.
Subdomains are not matched by wildcard (e.g. `allowed_domains=foo.example.com`
matches `foo.example.com` but not `sub.foo.example.com`).

```bash
# Set allowed_domains on an entity
bao write identity/entity name=app-server \
    metadata.allowed_domains=www.example.com,api.example.com

# Create an entity alias and token role
bao write identity/entity-alias \
    name=app-server-alias \
    mount_accessor=auth_token_xxx \
    canonical_id=<ENTITY_ID>

bao write auth/token/roles/app-role \
    allowed_entity_aliases="app-server-alias"


TOKEN=$(bao write -field=auth.client_token auth/token/create/app-role \
    entity_alias=app-server-alias)
```

### enroll/retrieve/**`<ID>`**

Polls the status of an enrollment. Returns `pending`, `in_progress`,
`completed`, `error`, or `cancelled` status. On `completed`, the full
certificate bundle is included.

| State | Output Fields |
|---|---|
| **completed** | `id`, `state`, `domains`, `certificate` (PEM bundle), `issued_at`, `not_after`, `message` |
| **pending** / **in_progress** | `id`, `state`, `domains`, `message` |
| **error** | `id`, `state`, `domains`, `error` |
| **cancelled** | `id`, `state`, `domains` |

### enroll/retrieve

Polls enrollment status with the ID passed in the request body.

```bash
bao write dnsplugin/enroll/retrieve id=<ID>
```

## REVOKE PATH

### revoke

Revokes a certificate by sending a revoke request to the ACME CA, or cancels
a pending enrollment.

The plugin stores the ACME account URI from the initial `config/create`
registration. When revoking, the account URI is passed to the lego ACME
client, which includes it as the JWS `kid` header. Let's Encrypt staging
requires this header (rather than embedding the account JWK) for revocation.

| Parameter | Type | Description |
|---|---|---|
| **certificate** | string | PEM-encoded certificate to revoke |
| **id** | string | Enrollment ID to cancel (marks enrollment as `cancelled`) |

| Output Field | Type | Description |
|---|---|---|
| **message** | string | Confirmation string |
| **serial** | string | Certificate serial number — only present when revoking by certificate |
| **domains** | []string | Domains of the cancelled enrollment — only present when revoking by enrollment ID |

```bash
bao write dnsplugin/revoke certificate="$(cat /tmp/server.crt)"
bao write dnsplugin/revoke id=<ENROLLMENT_ID>
```

## CONFIGURATION

### ACME Account Setup

The ACME account holds the private key used to communicate with the CA. The
plugin generates a fresh RSA-2048 key on each `config/create` call and stores
the account URI for use during revocation. If the plugin is restarted with
persistent storage, the ACME account (email, key, and URI) is loaded
automatically.

```bash
bao write dnsplugin/config/create \
    email=certificates@example.com \
    acme_url=https://acme-staging-v02.api.letsencrypt.org/directory
```

### Zone-Based Role Matching

The `zone` attribute specifies the DNS zone the API key controls (e.g.
`example.com`). It is passed to lego as the `ZONE` and `{PROVIDER}_ZONE`
environment variables — providers that need explicit zone identification
(Route53's `AWS_HOSTED_ZONE_ID`, etc.) will pick it up; most providers resolve
the zone from the domain automatically and ignore it.

During enrollment, a domain matches a role if the domain equals the zone or is a
subdomain of it (e.g. zone `example.com` matches `foo.example.com`). This
determines which DNS provider's credentials are used for the challenge.

### Provider Credential Mapping

The plugin uses the go-acme/lego library, which expects DNS provider
credentials as environment variable names. The plugin accepts credentials as
any string-valued keys in the role configuration. Keys are converted to
uppercase and passed as-is to lego — no auto-prefixing.

```bash
bao write dnsplugin/config/roles/cloudflare \
    provider=cloudflare \
    zone=example.com \
    CLOUDFLARE_DNS_API_TOKEN=cfut_token
```

The role key `CLOUDFLARE_DNS_API_TOKEN` becomes the env var
`CLOUDFLARE_DNS_API_TOKEN`. Use the exact env var names that lego expects
for each provider.

The zone value is set as both `ZONE` and `{PROVIDER}_ZONE` (e.g.
`CLOUDFLARE_ZONE`) environment variables, which providers that need explicit
zone identification will use.

### Supported Providers

Any provider supported by go-acme/lego is available. Common examples:

| Provider | Environment Variables |
|---|---|
| `cloudflare` | `CLOUDFLARE_DNS_API_TOKEN` |
| `route53` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
| `gandi` | `GANDI_API_KEY` |
| `namecheap` | `NAMECHEAP_API_KEY`, `NAMECHEAP_API_USER` |
| `dnsimple` | `DNSIMPLE_PERSONAL_ACCESS_TOKEN` |
| `akamai` | `AKAMAI_EDGERC_PATH` |

### CSR Parsing

The plugin extracts domain names from the CSR's Subject Alternative Name (SAN)
extension. If the CSR has no SAN, it falls back to the Common Name field.
Only DNS names are included; IP addresses are ignored.

## ENROLLMENT FLOW

The certificate issuance flow is asynchronous:

1. Entity sends CSR via `enroll/new` with its entity token
2. Plugin resolves the entity's metadata from OpenBao via `EntityInfo` RPC
3. Plugin verifies `allowed_domains` is set and each CSR domain is in the list
4. Plugin extracts domain names from the CSR's SAN/CN
5. Each domain is matched against configured role zones to find the DNS provider
6. The first matching role determines the provider and credentials
7. DNS-01 challenge is initiated via the matched provider
8. Plugin returns immediately with enrollment ID and pending state
9. Plugin polls the CA until the challenge is complete
10. Plugin stores the issued certificate and ACME account URI
11. Entity polls `enroll/retrieve/<ID>` until state is `completed`

Typical total time: 30–120 seconds depending on DNS propagation and CA
processing speed.

## Examples

### 1. Generate a CSR

```bash
openssl req -new -newkey rsa:2048 -nodes \
    -keyout /tmp/server.key \
    -out /tmp/server.csr \
    -subj "/CN=foo.example.com" \
    -addext "subjectAltName=DNS:foo.example.com"
```

### 2. Create or update the entity with `allowed_domains`

```bash
bao write identity/entity/name/foo \
    metadata.allowed_domains="foo.example.com"
```

### 3. Create the AppRole role (if it doesn't exist)

```bash
bao write auth/approle/role/foo \
    token_policies=dns-acme-enroll \
    token_period=2160h \
    token_type=service
```

### 4. Get the AppRole `role_id`

```bash
bao read -field=role_id auth/approle/role/foo
```

### 5. Create the entity alias (name **must** be the `role_id`)

```bash
bao write identity/entity-alias \
    name=<role_id-from-step-4> \
    mount_accessor=auth_approle_<identifier> \
    canonical_id=<foo-entity-id>
```

### 6. Generate a `secret_id` and log in

```bash
# Generate secret_id
SECRET_ID=$(bao write -force -field=secret_id auth/approle/role/foo/secret-id)

# Create login payload
cat > approle-login.json << EOF
{
  "role_id": "<role_id-from-step-4>",
  "secret_id": "$SECRET_ID"
}
EOF

# Login
bao write auth/approle/login @approle-login.json
```

### 7. Enroll the CSR

```bash
CSR=$(base64 -w 0 /tmp/server.csr)
ID=$(bao write -field=id dns-acme/enroll/new csr="$CSR")
```

### 8. Poll for completion

```bash
bao read dns-acme/enroll/retrieve/$ID
```

### 9. Retrieve the certificate

```bash
bao read dns-acme/enroll/retrieve/$ID -format=json | \
    jq -r '.data.certificate' > /tmp/server.crt
```

### 10. Revoke the certificate (when needed)

```bash
bao write dns-acme/revoke certificate="$(cat /tmp/server.crt)"
```

---

### Important Notes

- The **entity alias name must exactly match the AppRole `role_id`** (the UUID returned in step 4). Using a friendly name will not work.
- The `allowed_domains` metadata on the entity is **required**. Enrollment will fail if it is missing or if the CSR domains do not match.
- After login, verify the correct entity with:

  ```bash
  bao token lookup
  ```

### Authorization Test Cases

```bash
# ✅ Entity with allowed_domains=www.example.com, www succeeds
bao write dnsplugin/enroll/new csr="..."   # → pending

# ✅ Entity with allowed_domains=www.example.com, www.example.com succeeds
#    (exact match, no wildcard)

# ❌ Entity with allowed_domains=www.example.com, sub.www.example.com fails
#    domain "sub.www.example.com" not in entity's allowed_domains

# ❌ Entity with metadata but no allowed_domains fails
#    entity metadata missing allowed_domains

# ❌ Entity without metadata fails
#    entity metadata not found, ensure the entity has allowed_domains metadata
```

## ACL POLICIES

OpenBao ACL policies control path-level access to the plugin. Below is a typical policy for certificate enrollment.
Note that allowed names are directly enforced by the plugin not the policy.
```
# Minimal policy for a dns-acme enrollment and self renewal.  Create a token with this policy and it can enroll and renew indefinitely
# Self renewal
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Main enrollment
path "dnsplugin/enroll/new" {
  capabilities = ["create", "update"]
}

# Retrieve operations
path "dnsplugin/enroll/retrieve" {
  capabilities = ["create", "read"]
}

path "dnsplugin/enroll/retrieve/*" {
  capabilities = ["read"]
}

# Revoke
path "dnsplugin/revoke" {
  capabilities = ["create", "update"]
}

# If the plugin needs to read entities or aliases during enrollment
path "identity/entity-alias" {
  capabilities = ["read", "list"]
}

path "identity/entity/name/video3" {
  capabilities = ["read"]
}
```

## ENVIRONMENT VARIABLES

No environment variables are required. All configuration is stored in OpenBao
storage. The following environment variables affect plugin startup:

| Variable | Description |
|---|---|
| `BAO_ADDR` | OpenBao server address (defaults to https://127.0.0.1:8200) |
| `BAO_TOKEN` | Authentication token |
| `BAO_SKIP_VERIFY` | Skip TLS certificate verification (default: false) |

## AUTHORS

The dns-acme plugin was developed for OpenBao by Michael Quinn
<mikerquinn> as an ACME DNS-01 secrets engine for automated certificate
provisioning with entity-based domain authorization.

The plugin uses the go-acme/lego library for ACME protocol support and
DNS-01 challenge resolution across 100+ DNS providers.

