# dnsacme-policy — OpenBao DNS-01 ACME Plugin

## NAME

**dnsacme-policy** — OpenBao plugin for ACME certificate issuance via DNS-01 challenges with role-based domain authorization

## DESCRIPTION

**dnsacme-policy** is an OpenBao secrets engine plugin that issues X.509
certificates from any ACME-compatible certificate authority (CA) using the
DNS-01 challenge mechanism.

Unlike most DNS providers, which only offer zone-level or account-level API
tokens that allow DNS record creation for any name within the zone, this plugin
adds a role-based authorization layer: a role maps a DNS provider credential to
a glob pattern of allowed domain names. An entity that requests a certificate
via a CSR must have the requesting domain authorized either by the role's
`allowed_names` or by the entity's `allowed_domains` metadata. This prevents a
server from enrolling for arbitrary names in the zone — it can only enroll for
names it is explicitly authorized for.

The plugin maintains its own internal storage for DNS role credentials and
ACME account state. The issuer runs asynchronously: enrollment requests return
immediately with a pending status, and the client polls the retrieve endpoint
until the certificate is issued.

## INSTALLATION

### Enable the Plugin

```
$ bao secrets enable -path=dnsplugin -plugin-name=dnsacme-plugin plugin
```

The plugin binary must be registered in the OpenBao plugin catalog before
enabling:

```
$ bao plugin register -sha256=<SHA256> secret dnsacme-plugin
$ bao secrets enable -path=dnsplugin -plugin-name=dnsacme-plugin plugin
```

### Enable TLS Verification

```
$ bao secrets enable -tls-required=true -path=dnsplugin -plugin-name=dnsacme-plugin plugin
```

## API PATHS

The following paths are available on the mounted secrets engine:

```
  dnsplugin/config/create
  dnsplugin/config
  dnsplugin/config/roles
  dnsplugin/config/roles/<ROLE>
  dnsplugin/enroll/new
  dnsplugin/enroll/retrieve/<ID>
  dnsplugin/enroll/retrieve
  dnsplugin/revoke
```

All paths support both `bao write` (data-based) and `bao read` (retrieval)
operations through the OpenBao key-value interface.

### `dnsplugin/config/create`

Creates an ACME account with a generated RSA-2048 keypair and registers it
with the ACME CA. Returns the account URI.

```
$ bao write dnsplugin/config/create acme_email=<EMAIL> acme_url=<URL>
```

| Input Field | Description |
|---|---|
| `acme_email` | ACME account email address (optional; CA may require it) |
| `acme_url` | ACME directory URL (defaults to Let's Encrypt production) |

| Output Field | Description |
|---|---|
| `email` | The registered email |
| `key` | The generated private key in PEM format |
| `uri` | ACME account URI |
| `message` | Confirmation string |

### `dnsplugin/config`

Retrieves the current ACME account configuration (email only).

```
$ bao read dnsplugin/config
```

### `dnsplugin/config/roles`

Lists all configured DNS provider roles.

```
$ bao read dnsplugin/config/roles
```

### `dnsplugin/config/roles/<ROLE>`

Create, update, or delete a DNS provider role. A role maps a DNS provider
name and credential set to a glob pattern of allowed domain names.

```
# Create or update
$ bao write dnsplugin/config/roles/<ROLE> provider=<PROVIDER> allowed_names=<NAMES> <CREDENTIALS>

# Read
$ bao read dnsplugin/config/roles/<ROLE>

# Delete
$ bao delete dnsplugin/config/roles/<ROLE>
```

| Input Field | Description |
|---|---|
| `provider` | DNS provider name (e.g. `cloudflare`, `route53`, `gandi`). Any provider supported by go-acme/lego is valid. |
| `allowed_names` | Comma-separated list of domain names or glob patterns. Wildcards: `*.example.com` matches `foo.example.com` but not `example.com`. |
| `<CREDENTIALS>` | One or more provider-specific credential keys. See [Provider Credential Mapping](#provider-credential-mapping) below. |

| Output Field | Description |
|---|---|
| `message` | Confirmation string |
| `name` | Role name |
| `provider` | DNS provider name |

### `dnsplugin/enroll/new`

Enrolls a CSR for certificate issuance. The CSR is parsed to extract
domain names, each domain is matched against configured role `allowed_names`
patterns to determine the DNS provider, and the DNS-01 challenge is initiated
asynchronously.

```
$ bao write dnsplugin/enroll/new csr=<BASE64_CSR>
```

| Input Field | Description |
|---|---|
| `csr` | CSR in PEM format, base64-encoded by the CLI |
| `acme_url` | Override ACME directory URL for this enrollment only |
| `acme_email` | Override the ACME account email for this enrollment only |
| `name` | Entity name (used for entity authorization when combined with metadata) |

| Output Field | Description |
|---|---|
| `id` | Enrollment identifier (hex string) |
| `state` | `"pending"` — DNS-01 challenge is in progress |
| `domains` | List of domains from the CSR |
| `message` | Human-readable status |
| `retrieve_url` | URL to poll for completion |

Entity authorization is applied when the request includes a `name` field and
`metadata` map. Authorization is checked against either the entity's
`allowed_domains` metadata attribute or against all role `allowed_names`
patterns. In dev CLI mode (no entity context), authorization is skipped.

### `dnsplugin/enroll/retrieve/<ID>`

Polls the status of an enrollment. Returns `pending`, `in_progress`,
`completed`, `error`, or `cancelled` status. On `completed`, the full
certificate bundle is included.

```
$ bao read dnsplugin/enroll/retrieve/<ID>
```

| State | Output Fields |
|---|---|
| `completed` | `id`, `state`, `domains`, `certificate` (PEM bundle), `issued_at`, `not_after`, `message` |
| `pending` / `in_progress` | `id`, `state`, `domains`, `message` |
| `error` | `id`, `state`, `domains`, `error` |
| `cancelled` | `id`, `state`, `domains`, `message` |

### `dnsplugin/enroll/retrieve`

Polls enrollment status with the ID passed in the request body.

```
$ bao write dnsplugin/enroll/retrieve id=<ID>
```

### `dnsplugin/revoke`

Revokes a certificate by sending a revoke request to the ACME CA.

```
$ bao write dnsplugin/revoke certificate=<CERT_PEM>
$ bao write dnsplugin/revoke id=<ENROLLMENT_ID>
```

| Input Field | Description |
|---|---|
| `certificate` | PEM-encoded certificate to revoke |
| `id` | Enrollment ID to cancel (marks enrollment as `"cancelled"`) |

| Output Field | Description |
|---|---|
| `message` | Confirmation string |
| `serial` | Certificate serial number |

## CONFIGURATION

### ACME Account Setup

The ACME account holds the private key used to communicate with the CA. The
plugin generates a fresh RSA-2048 key on each `config/create` call. If the
plugin is restarted (e.g. OpenBao dev container with inmem storage), the
account must be recreated.

```
$ bao write dnsplugin/config/create \
    acme_email=certificates@example.com \
    acme_url=https://acme-staging-v02.api.letsencrypt.org/directory
```

### DNS Provider Roles

Roles are the central authorization mechanism. Each role ties a DNS provider
to a glob pattern of allowed names. The plugin iterates all roles and finds
the first match against the CSR domains to determine which provider to use.

```
$ bao write dnsplugin/config/roles/cloudflare-main \
    provider=cloudflare \
    allowed_names="example.com,*.example.com" \
    CLOUDFLARE_DNS_API_TOKEN=cfut_mQ40...
```

```
$ bao write dnsplugin/config/roles/route53-staging \
    provider=route53 \
    allowed_names="staging.example.com" \
    AWS_ACCESS_KEY_ID=AKIA... \
    AWS_SECRET_ACCESS_KEY=wJalr...
```

Multiple roles can cover overlapping domains. The first match wins. Use
narrower patterns in earlier-registered roles to override broader ones.

### Provider Credential Mapping

The plugin uses the go-acme/lego library, which expects DNS provider
credentials as environment variable names. The plugin accepts credentials in
two forms:

**Form 1: Explicit env var name** (key contains an underscore)

```
CLOUDFLARE_DNS_API_TOKEN=cfut_token
```

The plugin passes the key directly to lego as-is: `CLOUDFLARE_DNS_API_TOKEN`.

**Form 2: Short key auto-prefixed** (key contains no underscore)

```
api_token=cfut_token
```

The plugin auto-prefixeds the key with the uppercase provider name:
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
2. Plugin extracts domain names, matches against role patterns
3. DNS-01 challenge is initiated via the matched provider
4. Plugin returns immediately with enrollment ID and pending state
5. Plugin polls the CA until the challenge is complete
6. Plugin stores the issued certificate
7. Entity polls `enroll/retrieve/<ID>` until state is `"completed"`

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
$ bao write dnsplugin/config/create \
    acme_email=certs@example.com \
    acme_url=https://acme-staging-v02.api.letsencrypt.org/directory

# 3. Create a DNS role
$ bao write dnsplugin/config/roles/cloudflare \
    provider=cloudflare \
    allowed_names="example.com,*.example.com" \
    CLOUDFLARE_DNS_API_TOKEN=cfut_mQ40...

# 4. Enroll the CSR
$ CSR=$(base64 -w 0 /tmp/server.csr)
$ bao write dnsplugin/enroll/new csr="$CSR"

# 5. Poll for completion (repeat until state is "completed")
$ bao read dnsplugin/enroll/retrieve/<ID>

# 6. On completion, extract the certificate
$ bao read dnsplugin/enroll/retrieve/<ID> -format=json |
  python3 -c "import json,sys; print(json.load(sys.stdin)['data']['certificate'])" \
  > /tmp/server.crt
```

### Renewal

Renewal uses the same enrollment flow with the same CSR (or a new one):

```bash
$ bao write dnsplugin/enroll/new csr="$CSR"
# Returns same enrollment ID; plugin re-issues the certificate
# (new not_after timestamp)
$ bao read dnsplugin/enroll/retrieve/<ID>
```

### Revocation

```bash
# Revoke by certificate
$ bao write dnsplugin/revoke certificate="$(cat /tmp/server.crt)"

# Or cancel a pending enrollment
$ bao write dnsplugin/revoke id=<ID>
```

## STORAGE KEYS

The plugin stores data in the following OpenBao key paths:

| Storage Key | Contents |
|---|---|
| `config/acme_key` | ACME account (email, private key) |
| `config/roles/<name>` | DNS provider role |
| `enroll/<id>` | Enrollment state (CSR, domains, status, certificate, timestamps) |

## ACL POLICIES

OpenBao ACL policies control path-level access to the plugin. Below are
example policies for common use cases.

### Administrator

Full access to all plugin paths.

```
path "dnsplugin/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

### Operator

Can create roles, enroll certificates, and retrieve/issue certificates,
but cannot delete roles or the ACME account.

```
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

Limited to a subset of domains via path wildcards. This policy allows
issuance for `*.staging.example.com` only, and read access to those
enrollments.

```
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

```
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
$ bao write auth/token/accessor/<ACCESSOR> \
    metadata=allowed_domains=example.com,*.example.com

# Or create a token with allowed_domains
$ bao write auth/token/create \
    policies=issuer \
    metadata=allowed_domains=staging.example.com
```

The plugin checks entity metadata during enrollment. If `allowed_domains` is
set, the CSR domains must be an exact match. If not set, the plugin falls
back to checking role `allowed_names` patterns.

### Namespace Policies

When using OpenBao namespaces, the plugin paths are relative to the namespace
root. A namespace-scoped policy:

```
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

The dnsacme-policy plugin was developed for OpenBao by Michael Quinn
<mikerquinn> as an ACME DNS-01 secrets engine for automated certificate
provisioning with role-based domain authorization.

The plugin uses the go-acme/lego library for ACME protocol support and
DNS-01 challenge resolution across 100+ DNS providers.

## VERSION

This document describes version 1.0 of the dnsacme-policy plugin for OpenBao.

June 7, 2026
