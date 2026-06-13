package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	cryptoPkg "github.com/mikerquinn/dns-acme/crypto"
	"github.com/mikerquinn/dns-acme/enroll"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathEnroll returns the enrollment paths (new + retrieve).
func pathEnroll(b *dnsacmeBackend) []*framework.Path {
	return []*framework.Path{
		pathEnrollNew(b),
		pathEnrollRetrieve(b),
	}
}

// pathEnrollNew extends the API with a `/enroll/new` endpoint.
func pathEnrollNew(b *dnsacmeBackend) *framework.Path {
	return &framework.Path{
		Pattern: "enroll/new",
		Fields: map[string]*framework.FieldSchema{
			"csr": {
				Type:        framework.TypeString,
				Description: "CSR in PEM format (auto-decoded if base64-encoded by the CLI)",
				Required:    true,
			},
			"acme_url": {
				Type:        framework.TypeString,
				Description: "Override ACME directory URL for this enrollment only",
			},
			"acme_email": {
				Type:        framework.TypeString,
				Description: "Override ACME account email for this enrollment only",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathEnroll,
				Summary:  "Enroll a CSR for certificate issuance",
			},
		},
		HelpSynopsis:    pathEnrollNewHelpSynopsis,
		HelpDescription: pathEnrollNewHelpDescription,
	}
}

// pathEnrollRetrieve extends the API with a `/enroll/retrieve` endpoint.
func pathEnrollRetrieve(b *dnsacmeBackend) *framework.Path {
	return &framework.Path{
		Pattern: "enroll/retrieve/?$",
		Fields: map[string]*framework.FieldSchema{
			"id": {
				Type:        framework.TypeString,
				Description: "Enrollment identifier (from request body or path parameter)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback:  b.pathEnrollRetrieve,
				Summary:   "Poll enrollment status (ID from path)",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback:  b.pathEnrollRetrieve,
				Summary:   "Poll enrollment status (ID from body)",
			},
		},
		HelpSynopsis:    pathEnrollRetrieveHelpSynopsis,
		HelpDescription: pathEnrollRetrieveHelpDescription,
	}
}

// pathEnroll creates a new certificate enrollment.
func (b *dnsacmeBackend) pathEnroll(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	csrStr, _ := d.GetOk("csr")
	acmeURL, _ := d.GetOk("acme_url")
	acmeEmail, _ := d.GetOk("acme_email")

	csrPEM, ok := csrStr.(string)
	if !ok || csrPEM == "" {
		return &logical.Response{Data: map[string]interface{}{"error": "CSR is required"}}, nil
	}

	acmeURLStr, _ := acmeURL.(string)
	acmeEmailStr, _ := acmeEmail.(string)

	// Try to base64 decode if the CSR looks like base64 (no PEM headers)
	csrPEMOut := csrPEM
	if !strings.Contains(csrPEMOut, "-----") {
		decoded, err := base64.StdEncoding.DecodeString(csrPEMOut)
		if err == nil && len(decoded) > 0 {
			csrPEMOut = string(decoded)
		}
	}

	csrInfo, err := cryptoPkg.ParseCSRFromString(csrPEMOut)
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "invalid CSR: " + err.Error()}}, nil
	}
	if len(csrInfo.Domains) == 0 {
		return &logical.Response{Data: map[string]interface{}{"error": "CSR has no domain names"}}, nil
	}

	// Extract entity metadata for authorization
	metadata := make(map[string]string)
	if md, ok := req.Headers["X-Entity-Metadata"]; ok {
		for _, s := range md {
			parts := strings.Split(s, ";")
			for _, part := range parts {
				kv := strings.SplitN(part, "=", 2)
				if len(kv) == 2 {
					metadata[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
				}
			}
		}
	}
	var entityID string
	if eid, ok := req.Headers["X-Entity-Id"]; ok && len(eid) > 0 {
		entityID = eid[0]
		_ = entityID // available for entity context in authorization
	}
	domain := ""
	if d, ok := req.Headers["X-Entity-Domain"]; ok && len(d) > 0 {
		domain = d[0]
	}

	// Validate entity authorization (skip if no entity context, e.g. dev CLI)
	if domain != "" && len(metadata) > 0 {
		if err := b.validateEntityAuthorization(ctx, req, domain, metadata, csrInfo.Domains); err != nil {
			return &logical.Response{Data: map[string]interface{}{"error": "entity not authorized: " + err.Error()}}, nil
		}
	}

	// Find matching role by checking if the domain falls within the role's zone
	var matchedProvider string
	var matchedCredentials map[string]interface{}
	roles, err := req.Storage.List(ctx, configKeyRoles)
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to list roles: " + err.Error()}}, nil
	}
	for _, roleName := range roles {
		role, err := b.getRole(ctx, req.Storage, roleName)
		if err != nil {
			continue
		}
		for _, domainName := range csrInfo.Domains {
			if zoneMatchesDomain(domainName, role.Zone) {
				matchedProvider = role.Provider
				matchedCredentials = role.Credentials
				break
			}
		}
		if matchedProvider != "" {
			break
		}
	}

	if matchedProvider == "" {
		domainsStr := strings.Join(csrInfo.Domains, ", ")
		return &logical.Response{Data: map[string]interface{}{
			"error":   fmt.Sprintf("no matching DNS role found for domains [%s] — ensure at least one role's zone covers one of the requested domains", domainsStr),
			"domains": csrInfo.Domains,
		}}, nil
	}

	enrollmentID := generateID()
	state := enroll.NewEnrollmentState(enrollmentID, csrPEMOut, csrInfo.Domains, acmeURLStr)
	if acmeEmailStr != "" {
		state.ACMEEmail = acmeEmailStr
	} else {
		state.ACMEEmail = b.acmeEmail
	}
	state.Provider = matchedProvider
	state.Credentials = matchedCredentials

	if err := b.enrollStore.CreateEnrollment(ctx, state); err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to create enrollment: " + err.Error()}}, nil
	}

	if b.issuer != nil {
		b.issuer.StartEnrollment(ctx, enrollmentID)
	}

	return &logical.Response{Data: map[string]interface{}{
		"id":             enrollmentID,
		"state":          "pending",
		"domains":        csrInfo.Domains,
		"message":        "enrollment initiated, DNS-01 challenge in progress",
		"retrieve_url":   "/enroll/retrieve/" + enrollmentID,
	}}, nil
}

// pathEnrollRetrieve polls enrollment status.
func (b *dnsacmeBackend) pathEnrollRetrieve(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id, _ := d.GetOk("id")
	idStr, ok := id.(string)
	if !ok || idStr == "" {
		// Try to get from path: enroll/retrieve/<id>
		parts := strings.Split(req.Path, "/")
		if len(parts) >= 4 {
			idStr = parts[3]
		}
	}

	if idStr == "" {
		return &logical.Response{Data: map[string]interface{}{"error": "enrollment ID is required"}}, nil
	}

	state, err := b.enrollStore.GetEnrollment(ctx, idStr)
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "enrollment not found: " + err.Error()}}, nil
	}

	switch state.State {
	case "pending", "in_progress":
		return &logical.Response{Data: map[string]interface{}{
			"id":      state.ID,
			"state":   state.State,
			"domains": state.Domains,
			"message": "enrollment in progress",
		}}, nil
	case "completed":
		return &logical.Response{Data: map[string]interface{}{
			"id":          state.ID,
			"state":       "completed",
			"domains":     state.Domains,
			"certificate": state.Certificate,
			"issued_at":   state.UpdatedAt.Format(time.RFC3339),
			"not_after":   state.NotAfter.Format(time.RFC3339),
			"message":     "certificate issued successfully",
		}}, nil
	case "error":
		return &logical.Response{Data: map[string]interface{}{
			"id":      state.ID,
			"state":   "error",
			"domains": state.Domains,
			"error":   state.Error,
		}}, nil
	case "cancelled":
		return &logical.Response{Data: map[string]interface{}{
			"id":      state.ID,
			"state":   "cancelled",
			"domains": state.Domains,
		}}, nil
	default:
		return &logical.Response{Data: map[string]interface{}{
			"id":      state.ID,
			"state":   state.State,
			"domains": state.Domains,
		}}, nil
	}
}

// validateEntityAuthorization checks whether the requesting entity is authorized for the requested domains.
func (b *dnsacmeBackend) validateEntityAuthorization(ctx context.Context, req *logical.Request, domain string, metadata map[string]string, domains []string) error {
	if allowedDomains, ok := metadata["allowed_domains"]; ok && allowedDomains != "" {
		allowedList := strings.Split(allowedDomains, ",")
		for _, requested := range domains {
			found := false
			for _, allowed := range allowedList {
				if strings.TrimSpace(allowed) == requested {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("domain %q not in entity's allowed_domains: %s", requested, allowedDomains)
			}
		}
		return nil
	}

	// Fallback: check role zones
	for _, requested := range domains {
		matched := false
		roles, err := req.Storage.List(ctx, configKeyRoles)
		if err != nil {
			continue
		}

		for _, roleName := range roles {
			role, err := b.getRole(ctx, req.Storage, roleName)
			if err != nil {
				continue
			}
			if zoneMatchesDomain(requested, role.Zone) {
				matched = true
				break
			}
		}

		if !matched {
			return fmt.Errorf("domain %q does not fall within any DNS provider role zone", requested)
		}
	}

	return nil
}

// zoneMatchesDomain checks if a domain falls within a DNS zone.
func zoneMatchesDomain(domain, zone string) bool {
	domain = strings.ToLower(domain)
	zone = strings.ToLower(zone)
	if domain == zone {
		return true
	}
	if strings.HasSuffix(domain, "."+zone) {
		return true
	}
	return false
}

// generateID creates a random hex ID.
func generateID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err == nil {
		return hex.EncodeToString(bytes)
	}
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

const (
	pathEnrollNewHelpSynopsis    = `Enroll a CSR for certificate issuance via DNS-01 ACME challenge.`
	pathEnrollNewHelpDescription = `
Submits a CSR (Certificate Signing Request) for certificate issuance.
The plugin extracts domain names from the CSR and matches them against
configured DNS provider roles. A matching role's zone must cover at
least one of the requested domains.

The enrollment is asynchronous — the response returns immediately with
an enrollment ID. Poll the retrieve endpoint until the certificate is
issued (typically 30-120 seconds).
`

	pathEnrollRetrieveHelpSynopsis    = `Poll the status of a certificate enrollment.`
	pathEnrollRetrieveHelpDescription = `
Returns the status of an enrollment. States include:
  - pending: DNS-01 challenge initiated
  - in_progress: Challenge being verified
  - completed: Certificate issued (includes certificate bundle)
  - error: Challenge failed (includes error message)
  - cancelled: Enrollment cancelled

On completed, the full certificate bundle (leaf + intermediates) is
included in the response.
`
)
