package main

import (
	"context"
	"crypto/x509"
	"strings"

	cryptoPkg "github.com/mikerquinn/dns-acme/crypto"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathRevoke returns the revoke path.
func pathRevoke(b *dnsacmeBackend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "revoke",
		Fields: map[string]*framework.FieldSchema{
			"certificate": {
				Type:        framework.TypeString,
				Description: "PEM-encoded certificate to revoke",
			},
			"id": {
				Type:        framework.TypeString,
				Description: "Enrollment ID to cancel (marks enrollment as cancelled)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback:  b.pathRevoke,
				Summary:   "Revoke a certificate or cancel a pending enrollment",
			},
		},
		HelpSynopsis:    pathRevokeHelpSynopsis,
		HelpDescription: pathRevokeHelpDescription,
		},
	}
}

// pathRevoke revokes a certificate or cancels a pending enrollment.
func (b *dnsacmeBackend) pathRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	certStr, _ := d.GetOk("certificate")
	id, _ := d.GetOk("id")

	certStrStr, _ := certStr.(string)
	idStr, _ := id.(string)

	// If enrollment ID is provided, cancel it
	if idStr != "" {
		state, err := b.enrollStore.GetEnrollment(ctx, idStr)
		if err != nil {
			return &logical.Response{Data: map[string]interface{}{"error": "enrollment not found: " + err.Error()}}, nil
		}
		state.State = "cancelled"
		b.enrollStore.UpdateEnrollment(ctx, state)
		return &logical.Response{Data: map[string]interface{}{
			"id":      idStr,
			"message": "enrollment cancelled",
			"domains": state.Domains,
		}}, nil
	}

	if certStrStr == "" {
		return &logical.Response{Data: map[string]interface{}{"error": "certificate or enrollment id is required"}}, nil
	}

	certParsed, err := cryptoPkg.ParseCertificate([]byte(certStrStr))
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "invalid certificate: " + err.Error()}}, nil
	}

	acmeURL := b.acmeURL
	if acmeURL == "" {
		acmeURL = defaultACMEURL
	}

	client, err := b.acmeClient(ctx)
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to create ACME client: " + err.Error()}}, nil
	}
	if client == nil {
		return &logical.Response{Data: map[string]interface{}{"error": "ACME account not configured"}}, nil
	}

	parsedCert, err := x509.ParseCertificate([]byte(certStrStr))
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to parse certificate: " + err.Error()}}, nil
	}

	if err := client.Certificate.Revoke(parsedCert.Raw); err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to revoke certificate: " + err.Error()}}, nil
	}

	return &logical.Response{Data: map[string]interface{}{
		"message":  "certificate revoked",
		"serial":   certParsed.SerialNumber.String(),
		"subject":  strings.Join(certParsed.DNSNames, ", "),
	}}, nil
}

const (
	pathRevokeHelpSynopsis    = `Revoke a certificate or cancel a pending enrollment.`
	pathRevokeHelpDescription = `
Revokes a certificate by sending a revoke request to the ACME CA, or
cancels a pending enrollment by enrollment ID.

When revoking by certificate, the certificate must have been issued by
this backend (the ACME account key is used for revocation).

When cancelling by enrollment ID, the enrollment state is set to
"cancelled" without contacting the CA.
`
)
