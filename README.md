# dns-acme

## NAME

**dns-acme** — OpenBao DNS-01 ACME certificate issuance plugin with role-based domain authorization

## DESCRIPTION

**dns-acme** is an OpenBao secrets engine plugin that issues X.509
certificates from any ACME-compatible certificate authority (CA) using the
DNS-01 challenge mechanism.

Most DNS providers only offer zone-level or account-level API tokens that allow
DNS record creation for any name within the zone. This plugin adds a role-based
authorization layer: a role maps a DNS provider credential to a DNS zone. An
entity that requests a certificate via a CSR must have the requesting domain
authorized either by the role's **zone** (the domain must equal the zone or be a
subdomain of it) or by the entity's **allowed_domains** metadata attribute. This
prevents a server from enrolling for arbitrary names in the zone.

The plugin maintains its own internal storage for DNS role credentials and
ACME account state. The issuer runs asynchronously: enrollment requests return
immediately with a pending status, and the client polls the retrieve endpoint
until the certificate is issued.

## SYNOPSIS

**bao secrets enable** `-path=<PATH>` `-plugin-name=<NAME>` `plugin`

**bao write** **<PATH>/config/create** `acme_email=`**`<EMAIL>`** `acme_url=`**`<URL>`**

**bao write** **<PATH>/config/roles/**`<NAME>`** `provider=`**`<PROVIDER>`** `zone=`**`<ZONE>`** `...`**`<CREDENTIALS>`**

**bao write** **<PATH>/enroll/new** `csr=`**`<CSR>`**

**bao read** **<PATH>/enroll/retrieve/**`<ID>`**

**bao write** **<PATH>/revoke** `certificate=`**`<CERT>`**

## INSTALLATION

### Enable the Plugin

Register the plugin binary in the OpenBao plugin catalog, then enable it:

```bash
bao plugin register -sha256=<SHA256> secret dns-acme
bao secrets enable -path=dnsplugin -plugin-name=dns-acme plugin
```

To require TLS for the mount:

```bash
bao secrets enable -tls-required=true -path=dnsplugin -plugin-name=dns-acme plugin
```

## API PATHS

The following paths are available on the mounted secrets engine:

| Path | Operation | Description |
|---|---|---|
| **<PATH>/config/create** | `bao write` | Create ACME account with generated RSA-2048 key |
| **<PATH>/config** | `bao read` | Read current ACME account email |
| **<PATH>/config/roles** | `bao list`/`bao read` | List configured DNS roles |
| **<PATH>/config/roles/**`<NAME>`** | `bao write`/`bao read`/`bao delete` | Create, read, or delete a DNS role |
| **<PATH>/enroll/new** | `bao write` | Enroll a CSR for certificate issuance |
| **<PATH>/enroll/retrieve/**`<ID>`** | `bao read` | Poll enrollment status and retrieve certificate |
| **<PATH>/enroll/retrieve** | `bao write` | Poll enrollment status (ID in body) |
| **<PATH>/revoke** | `bao write` | Revoke a certificate or cancel a pending enrollment |

All paths support both `bao write` (data-based) and `bao read` (retrieval)
operations through the OpenBao key-value interface.

## CONFIGURATION PATHS

### config/create

Creates an ACME account with a generated RSA-2048 keypair and registers it
with the ACME CA.

| Parameter | Type | Description |
|---|---|---|
| **email** / **acme_email** | string | ACME account email address (required; CA may require it) |
| **acme_url** | string | ACME directory URL (defaults to Let's Encrypt production) |

| Output Field | Type | Description |
|---|---|---|
| **email** | string | The registered email |
| **key** | string | The generated private key in PEM format |
| **uri** | string | ACME account URI |
| **message** | string | Confirmation string |

```bash
bao write dnsplugin/config/create acme_email=certs@example.com
bao write dnsplugin/config/create acme_email=certs@example.com acme_url=https://acme-staging-v02.api.letsencrypt.org/directory
```

### config

Retrieves the current ACME account configuration (email only).

```bash
bao read dnsplugin/config
```

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
| **zone** | string | DNS zone the API key controls (e.g. `example.com`, `staging.example.com`). Required. The API key must have permissions for this zone and all subdomains. Passed to lego as the `ZONE` and `{PROVIDER}_ZONE` env vars. |
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
fallback). Each domain is matched against configured role zones — the first role
whose zone equals the domain or is a parent of it wins. If no matching role is
found, enrollment fails immediately with an error. If a role is found, the DNS-01
challenge is initiated asynchronously.

| Parameter | Type | Description |
|---|---|---|
| **csr** | string | CSR in PEM format (auto-decoded if base64-encoded by the CLI) |
| **acme_url** | string | Override ACME directory URL for this enrollment only |
| **acme_email** | string | Override the ACME account email for this enrollment only |

| Output Field | Type | Description |
|---|---|---|
| **id** | string | Enrollment identifier (hex string) — present only on success |
| **state** | string | `pending` — DNS-01 challenge is in progress — present only on success |
| **domains** | []string | List of domains from the CSR |
| **message** | string | Human-readable status — present only on success |
| **retrieve_url** | string | URL to poll for completion — present only on success |
| **error** | string | Error message — present when no matching role is found for the requested domains |

Entity authorization is applied when the request includes entity headers
(`X-Entity-Id`, `X-Entity-Metadata`, `X-Entity-Domain`). Authorization is
checked against either the entity's `allowed_domains` metadata attribute (exact
match) or against all role zones (zone-hierarchy match). In dev CLI mode (no
entity context), authorization is skipped.

### enroll/retrieve/**`<ID>`**

Polls the status of an enrollment. Returns `pending`, `in_progress`,
`completed`, `error`, or `cancelled` status. On `completed`, the full
certificate bundle is included.

| State | Output Fields |
|---|---|
| **completed** | `id`, `state`, `domains`, `certificate` (PEM bundle), `issued_at`, `not_after`, `message` |
| **pending** / **in_progress** | `id`, `state`, `domains`, `message` |
| **error** | `id`, `state`, `domains`, `error` |
| **cancelled** | `id`, `state`, `domains`, `message` |

### enroll/retrieve

Polls enrollment status with the ID passed in the request body.

```bash
bao write dnsplugin/enroll/retrieve id=<ID>
```

## REVOKE PATH

### revoke

Revokes a certificate by sending a revoke request to the ACME CA, or cancels
a pending enrollment.

| Parameter | Type | Description |
|---|---|---|
| **certificate** | string | PEM-encoded certificate to revoke |
| **id** | string | Enrollment ID to cancel (marks enrollment as `cancelled`) |

| Output Field | Type | Description |
|---|---|---|
| **message** | string | Confirmation string |
| **serial** | string | Certificate serial number |

```bash
bao write dnsplugin/revoke certificate=<CERT_PEM>
bao write dnsplugin/revoke id=<ENROLLMENT_ID>
```

## CONFIGURATION

### ACME Account Setup

The ACME account holds the private key used to communicate with the CA. The
plugin generates a fresh RSA-2048 key on each `config/create` call. If the
plugin is restarted (e.g. OpenBao dev container with inmem storage), the
account must be recreated.

```bash
bao write dnsplugin/config/create \
    acme_email=certificates@example.com \
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
replaces the former `allowed_names` glob pattern mechanism.

The zone is **not** a permissions mechanism — the entity's `allowed_domains`
metadata attribute is the only authorization check.

### Provider Credential Mapping

The plugin uses the go-acme/lego library, which expects DNS provider
credentials as environment variable names. The plugin accepts credentials in
two forms:

**Form 1: Explicit env var name** (key contains an underscore)

```bash
CLOUDFLARE_DNS_API_TOKEN=cfut_token
```

The plugin passes the key directly to lego as-is: `CLOUDFLARE_DNS_API_TOKEN`.

**Form 2: Short key auto-prefixed** (key contains no underscore)

```bash
api_token=cfut_token
```

The plugin auto-prefixes the key with the uppercase provider name:
`CLOUDFLARE_API_TOKEN`.

Form 1 is preferred when the provider name contains multiple words
(e.g., `CLOUDFLARE_DNS_API_TOKEN` vs `CLOUDFLARE_API_TOKEN`).

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

1. Entity sends CSR via `enroll/new`
2. Plugin extracts domain names from the CSR's SAN/CN
3. Each domain is matched against configured role zones (domain equals zone or is a subdomain)
4. If no matching role is found, the request fails immediately with an error
5. The first matching role determines the DNS provider and credentials
6. DNS-01 challenge is initiated via the matched provider
7. Plugin returns immediately with enrollment ID and pending state
8. Plugin polls the CA until the challenge is complete
9. Plugin stores the issued certificate
10. Entity polls `enroll/retrieve/<ID>` until state is `completed`

Typical total time: 30–120 seconds depending on DNS propagation and CA
processing speed.

## EXAMPLES

### Full Workflow

```bash
# 1. Generate a CSR
openssl req -new -newkey rsa:2048 -nodes \
    -keyout /tmp/server.key \
    -out /tmp/server.csr \
    -subj "/CN=www.example.com" \
    -addext "subjectAltName=DNS:www.example.com,DNS:mail.example.com"

# 2. Create an ACME account
bao write dnsplugin/config/create \
    acme_email=certs@example.com \
    acme_url=https://acme-staging-v02.api.letsencrypt.org/directory

# 3. Create a DNS role
bao write dnsplugin/config/roles/cloudflare \
    provider=cloudflare \
    zone=example.com \
    CLOUDFLARE_DNS_API_TOKEN=cfut_mQ40...

# 4. Enroll the CSR
CSR=$(base64 -w 0 /tmp/server.csr)
bao write dnsplugin/enroll/new csr="$CSR"

# 5. Poll for completion (repeat until state is "completed")
bao read dnsplugin/enroll/retrieve/<ID>

# 6. On completion, extract the certificate
bao read dnsplugin/enroll/retrieve/<ID> -format=json |
    python3 -c "import json,sys; print(json.load(sys.stdin)['data']['certificate'])" \
    > /tmp/server.crt
```

### Renewal

Renewal uses the same enrollment flow with the same CSR (or a new one):

```bash
bao write dnsplugin/enroll/new csr="$CSR"
# Returns same enrollment ID; plugin re-issues the certificate
# (new not_after timestamp)
bao read dnsplugin/enroll/retrieve/<ID>
```

### Revocation

```bash
# Revoke by certificate
bao write dnsplugin/revoke certificate="$(cat /tmp/server.crt)"

# Or cancel a pending enrollment
bao write dnsplugin/revoke id=<ID>
```

## STORAGE KEYS

The plugin stores data in the following OpenBao key paths:

| Storage Key | Contents |
|---|---|
| `config/acme_email` | ACME account email |
| `config/acme_key` | ACME account private key (PEM) |
| `config/roles/<name>` | DNS provider role (JSON: name, provider, zone, credentials) |
| `enroll/<id>` | Enrollment state (JSON: CSR, domains, provider, credentials, status, certificate, timestamps) |

## ACL POLICIES

OpenBao ACL policies control path-level access to the plugin. Below are
example policies for common use cases.

### Administrator

Full access to all plugin paths.

```bash
path "dnsplugin/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
```

### Operator

Can create roles, enroll certificates, and retrieve/issue certificates,
but cannot delete roles or the ACME account.

```bash
path "dnsplugin/config" {
    capabilities = ["read"]
}

path "dnsplugin/config/create" {
    capabilities = ["create"]
}

path "dnsplugin/config/roles" {
    capabilities = ["create", "read", "list"]
}

path "dnsplugin/config/roles/*" {
    capabilities = ["create", "read", "update", "delete"]
}

path "dnsplugin/enroll/new" {
    capabilities = ["create"]
}

path "dnsplugin/enroll/retrieve/*" {
    capabilities = ["read"]
}

path "dnsplugin/enroll/retrieve" {
    capabilities = ["create"]
}

path "dnsplugin/revoke" {
    capabilities = ["create"]
}
```

### Issuer

Limited to a subset of domains via role name prefixes. This policy allows
issuance for roles whose names start with `staging-` and read access to those
enrollments.

```bash
path "dnsplugin/config/roles/staging*" {
    capabilities = ["create", "read", "update"]
}

path "dnsplugin/enroll/new" {
    capabilities = ["create"]
}

path "dnsplugin/enroll/retrieve/*" {
    capabilities = ["read"]
}
```

### Read-Only Auditor

Can list roles and read enrollments but cannot create or update anything.

```bash
path "dnsplugin/config" {
    capabilities = ["read"]
}

path "dnsplugin/config/roles" {
    capabilities = ["list"]
}

path "dnsplugin/config/roles/*" {
    capabilities = ["read"]
}

path "dnsplugin/enroll/retrieve/*" {
    capabilities = ["read"]
}
```

### Entity Metadata Authorization

When using entity metadata for authorization, attach the `allowed_domains`
attribute to an entity or token:

```bash
# Set allowed_domains on an entity
bao write auth/token/accessor/<ACCESSOR> \
    metadata=allowed_domains=example.com,*.example.com

# Or create a token with allowed_domains
bao write auth/token/create \
    policies=issuer \
    metadata=allowed_domains=staging.example.com
```

The plugin checks entity metadata during enrollment. If `allowed_domains` is
set, the CSR domains must be an exact match against the listed values. If not
set, the plugin falls back to checking role zone attributes (the domain must
equal the zone or be a subdomain of it).

### Namespace Policies

When using OpenBao namespaces, the plugin paths are relative to the namespace
root. A namespace-scoped policy:

```bash
path "sys/mounts/dnsplugin" {
    capabilities = ["create", "read", "update", "delete"]
}

path "plugin/dnsplugin" {
    capabilities = ["read"]
}

path "dnsplugin/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
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
provisioning with role-based domain authorization.

The plugin uses the go-acme/lego library for ACME protocol support and
DNS-01 challenge resolution across 100+ DNS providers.

## VERSION HISTORY

### v1.0.1 — June 7, 2026

- Immediate error on `enroll/new` when no matching role is found (previously created a `pending` enrollment that errored on polling)
- Improved error messages for no-matching-role and unknown-provider cases

### v1.0 — June 7, 2026

Initial release.

## VERSION

This document describes version 1.0.1 of the dns-acme plugin for OpenBao.
