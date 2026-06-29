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
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathEnroll,
				Summary:  "Enroll a CSR for certificate issuance",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathEnroll,
				Summary:  "Enroll a CSR for certificate issuance",
			},
		},
		HelpSynopsis:    pathEnrollNewHelpSynopsis,
		HelpDescription: pathEnrollNewHelpDescription,
	}
}

// pathEnrollRetrieve extends the API with a `/enroll/retrieve/<id>` endpoint.
func pathEnrollRetrieve(b *dnsacmeBackend) *framework.Path {
	return &framework.Path{
		Pattern: "enroll/retrieve/" + framework.GenericNameRegex("id"),
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

	csrPEM, ok := csrStr.(string)
	if !ok || csrPEM == "" {
		return &logical.Response{Data: map[string]interface{}{"error": "CSR is required"}}, nil
	}

	acmeURLStr := b.acmeURL

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

	// Resolve entity metadata from OpenBao (authoritative, set by admin).
	// req.EntityID is populated by OpenBao from the token's entity.
	var entityMetadata map[string]string
	if req.EntityID != "" {
		ent, err := b.System().EntityInfo(req.EntityID)
		if err == nil && ent != nil {
			entityMetadata = ent.Metadata
			if b.logger != nil {
				b.logger.Info("resolved entity metadata", "entity_id", req.EntityID, "metadata", entityMetadata)
			}
		}
	}

	// Validate entity authorization — allowed_domains is required
	if len(entityMetadata) == 0 {
		return &logical.Response{Data: map[string]interface{}{"error": "entity metadata not found, ensure the entity has allowed_domains metadata"}}, nil
	}
	if allowedDomains, ok := entityMetadata["allowed_domains"]; !ok || allowedDomains == "" {
		return &logical.Response{Data: map[string]interface{}{"error": "entity metadata missing allowed_domains"}}, nil
	}
	if err := b.validateEntityAuthorization(ctx, req, entityMetadata, csrInfo.Domains); err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "entity not authorized: " + err.Error()}}, nil
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
	state.Provider = matchedProvider
	state.Credentials = matchedCredentials

	if err := b.enrollStore.CreateEnrollment(ctx, state); err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to create enrollment: " + err.Error()}}, nil
	}

	if b.issuer == nil {
		b.logger.Error("issuer is nil, enrollment will not be processed")
	} else {
		b.logger.Info("starting enrollment", "id", enrollmentID)
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

	// Resolve entity metadata from OpenBao (authoritative, set by admin).
	if req.EntityID != "" {
		ent, err := b.System().EntityInfo(req.EntityID)
		if err == nil && ent != nil && ent.Metadata != nil {
			if allowedDomains, ok := ent.Metadata["allowed_domains"]; ok && allowedDomains != "" {
				// Verify enrollment domains are within the entity's allowed domains
				if err := b.validateEntityAuthorization(ctx, req, ent.Metadata, state.Domains); err != nil {
					return &logical.Response{Data: map[string]interface{}{"error": "entity not authorized: " + err.Error()}}, nil
				}
			}
		}
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
// The entity's authoritative metadata is resolved from OpenBao via the entity's token.
// allowed_domains is a comma-separated list of domains the entity is authorized to enroll for.
func (b *dnsacmeBackend) validateEntityAuthorization(ctx context.Context, req *logical.Request, metadata map[string]string, domains []string) error {
	allowedDomains := metadata["allowed_domains"]
	allowedList := strings.Split(allowedDomains, ",")
	for _, requested := range domains {
		found := false
		requestedLower := strings.ToLower(requested)
		for _, allowed := range allowedList {
			if strings.ToLower(strings.TrimSpace(allowed)) == requestedLower {
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
