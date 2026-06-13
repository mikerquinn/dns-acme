package main

import (
	"context"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/mikerquinn/dns-acme/storage"
)

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// dnsacmeBackend wraps the Plugin logic as a logical.Backend for OpenBao.
type dnsacmeBackend struct {
	*framework.Backend
	*Plugin
	logger hclog.Logger
}

// backend defines the target API backend for OpenBao.
func backend() *dnsacmeBackend {
	b := &dnsacmeBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		Paths: framework.PathAppend(
			pathConfig(b),
			pathConfigCreate(b),
			pathConfigRoles(b),
			pathEnroll(b),
			pathRevoke(b),
		),
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"config",
				"config/*",
				"config/create",
				"enroll/new",
				"enroll/retrieve",
				"enroll/retrieve/*",
				"revoke",
			},
			SealWrapStorage: []string{
				"config",
				"config/role/*",
			},
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}

	return b
}

// reset clears all cached state (called from Plugin).
func (b *dnsacmeBackend) reset() {
	b.Plugin.reset()
}

// invalidate clears an existing configuration in the backend.
func (b *dnsacmeBackend) invalidate(ctx context.Context, key string) {
	if key == "config" || strings.HasPrefix(key, "config/") || strings.HasPrefix(key, "config/role/") {
		b.reset()
	}
}

// handleConfigCreate creates a new ACME account with a generated key.
func handleConfigCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	email, _ := d.GetOk("email")
	acmeURL, _ := d.GetOk("acme_url")

	emailStr, _ := email.(string)
	acmeURLStr, _ := acmeURL.(string)

	if emailStr == "" {
		return &logical.Response{Data: map[string]interface{}{"error": "email is required"}}, nil
	}

	// Generate a new RSA private key
	acmeKeyPEM, privateKey, err := generateKey()
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to generate ACME key: " + err.Error()}}, nil
	}

	// Determine ACME server URL
	if acmeURLStr == "" {
		acmeURLStr = defaultACMEURL
	}

	// Create a temporary ACME user for registration
	user := &acmeUser{email: emailStr, privateKey: privateKey, reg: nil}

	// Create ACME client and register the account
	config := lego.NewConfig(user)
	config.CADirURL = acmeURLStr
	config.Certificate.KeyType = certcrypto.RSA2048
	config.UserAgent = "openbao-dnsacme-plugin"

	client, err := lego.NewClient(config)
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to create ACME client: " + err.Error()}}, nil
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to register ACME account: " + err.Error()}}, nil
	}
	user.SetRegistration(reg)

	// Store the account using the plugin's shared config store (same backend used by enrollment reads)
	acmeAcc := &storage.ACMEAccount{Email: emailStr, Key: acmeKeyPEM}
	if err := globalImpl.configStore.SetACMEAccount(ctx, acmeAcc); err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to store ACME account: " + err.Error()}}, nil
	}

	// Update plugin's in-memory state
	return &logical.Response{Data: map[string]interface{}{
		"message": "ACME account created and registered",
		"email":   emailStr,
		"key":     acmeKeyPEM,
		"uri":     reg.URI,
	}}, nil
}

// backendHelp should contain help information for the backend.
const backendHelp = `
The DNS-01 ACME secrets backend issues X.509 certificates from any
ACME-compatible certificate authority (CA) using the DNS-01 challenge
mechanism.

DNS provider credentials are stored as roles, each mapping a provider to
a DNS zone. Certificate enrollment is asynchronous — an enrollment ID
is returned immediately, and the client polls the retrieve endpoint
until the certificate is issued.
`
