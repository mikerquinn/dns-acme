package main

import (
	"context"
	"crypto"
	"fmt"

	"github.com/go-acme/lego/v4/registration"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/mikerquinn/dns-acme/storage"
)

const (
	configKeyACMEEmail = "config/acme_email"
	configKeyACMEKey   = "config/acme_key"
	configKeyACMEURL   = "config/acme_url"
	configKeyRoles     = "config/role/"
)

const defaultACMEURL = "https://acme-v02.api.letsencrypt.org/directory"

// pathConfig returns the config path.
func pathConfig(b *dnsacmeBackend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"email": {
				Type:        framework.TypeString,
				Description: "ACME account email address",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Email",
					Sensitive: false,
				},
			},
			"key": {
				Type:        framework.TypeString,
				Description: "ACME account private key (PEM format)",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Key",
					Sensitive: true,
				},
			},
			"acme_url": {
				Type:        framework.TypeString,
				Description: "ACME directory URL (defaults to Let's Encrypt production)",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "ACME URL",
					Sensitive: false,
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				Summary:  "Get ACME account configuration",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				Summary:  "Create or update ACME account configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				Summary:  "Create or update ACME account configuration",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
				Summary:  "Delete ACME account configuration",
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
		},
	}
}

// pathConfigExistenceCheck verifies if the configuration exists.
func (b *dnsacmeBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	keys, err := req.Storage.List(ctx, "config/")
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}
	return len(keys) > 0, nil
}

// pathConfigRead reads the configuration and outputs non-sensitive information.
func (b *dnsacmeBackend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	email := b.acmeEmail
	if email == "" {
		entry, err := req.Storage.Get(ctx, configKeyACMEEmail)
		if err == nil && entry != nil {
			email = string(entry.Value)
		}
	}
	if email == "" {
		return &logical.Response{Data: map[string]interface{}{"error": "ACME account not configured"}}, nil
	}

	acmeURL := b.acmeURL
	if acmeURL == "" {
		entry, err := req.Storage.Get(ctx, configKeyACMEURL)
		if err == nil && entry != nil {
			acmeURL = string(entry.Value)
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"email": email,
			"acme_url": acmeURL,
		},
	}, nil
}

// pathConfigWrite updates the configuration for the backend.
func (b *dnsacmeBackend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	createOperation := (req.Operation == logical.CreateOperation)

	email, _ := d.GetOk("email")
	key, _ := d.GetOk("key")
	acmeURL, _ := d.GetOk("acme_url")

	emailStr, _ := email.(string)
	keyStr, _ := key.(string)
	acmeURLStr, _ := acmeURL.(string)

	// Handle aliases for config/create path
	if emailStr == "" {
		if alias, ok := d.GetOk("acme_email"); ok {
			if s, ok := alias.(string); ok && s != "" {
				emailStr = s
			}
		}
	}
	if keyStr == "" {
		if alias, ok := d.GetOk("acme_key"); ok {
			if s, ok := alias.(string); ok && s != "" {
				keyStr = s
			}
		}
	}

	if emailStr == "" {
		return &logical.Response{Data: map[string]interface{}{"error": "email is required"}}, nil
	}
	if keyStr == "" && createOperation {
		return &logical.Response{Data: map[string]interface{}{"error": "key is required for creation"}}, nil
	}

	if keyStr != "" {
		if _, err := parseKey([]byte(keyStr)); err != nil {
			return &logical.Response{Data: map[string]interface{}{"error": "invalid key: " + err.Error()}}, nil
		}
	}

	// Load existing account to preserve URI
	existing, _ := b.configStore.GetACMEAccount(ctx)
	uriStr := ""
	if existing != nil {
		uriStr = existing.URI
	}

	// Build the ACME account to store in the shared configStore
	account := &storage.ACMEAccount{
		Email: emailStr,
		Key:   keyStr,
		URL:   acmeURLStr,
		URI:   uriStr,
	}
	if err := b.configStore.SetACMEAccount(ctx, account); err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to store ACME account: " + err.Error()}}, nil
	}

	// Update plugin in-memory state
	b.acmeEmail = emailStr
	b.acmeKeyPEM = keyStr
	b.acmeURL = acmeURLStr
	b.acmeURI = account.URI

	// Reset client so next invocation picks up new config
	b.reset()

	return nil, nil
}

// pathConfigDelete removes the configuration.
func (b *dnsacmeBackend) pathConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configKeyACMEEmail); err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to delete email: " + err.Error()}}, nil
	}
	if err := req.Storage.Delete(ctx, configKeyACMEKey); err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to delete key: " + err.Error()}}, nil
	}
	req.Storage.Delete(ctx, configKeyACMEURL)

	b.reset()

	return nil, nil
}

// pathConfigHelpSynopsis summarizes the help text for the configuration.
const pathConfigHelpSynopsis = `Configure the ACME account for certificate issuance.`

// pathConfigHelpDescription describes the help text for the configuration.
const pathConfigHelpDescription = `
The DNS-01 ACME backend requires an ACME account with a private key
to communicate with the ACME certificate authority.

You must configure an ACME account before using the secrets backend.
The account can be created via config/create (auto-generates a key)
or via config/write (provides an existing key).
`

// pathConfigCreate returns the config/create path.
func pathConfigCreate(b *dnsacmeBackend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "config/create",
		Fields: map[string]*framework.FieldSchema{
			"email": {
				Type:        framework.TypeString,
				Description: "ACME account email address (required; CA may require it)",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Email",
					Sensitive: false,
				},
			},
			"acme_url": {
				Type:        framework.TypeString,
				Description: "ACME directory URL (defaults to Let's Encrypt production)",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "ACME URL",
					Sensitive: false,
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback:  b.pathConfigCreate,
				Summary:   "Create ACME account with generated RSA-2048 key",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback:  b.pathConfigCreate,
				Summary:   "Create ACME account with generated RSA-2048 key",
			},
		},
		HelpSynopsis:    pathConfigCreateHelpSynopsis,
		HelpDescription: pathConfigCreateHelpDescription,
		},
	}
}

const pathConfigCreateHelpSynopsis = `Create a new ACME account with a generated RSA-2048 keypair.`

const pathConfigCreateHelpDescription = `
Creates an ACME account with a fresh RSA-2048 private key and registers
it with the ACME certificate authority. The account key is stored and
can later be used for certificate operations.

If the plugin is restarted, the account must be recreated.
`

// Helper: acmeUser implements registration.User for ACME interactions.
type acmeUser struct {
	email      string
	privateKey crypto.PrivateKey
	reg        *registration.Resource
}

func (u *acmeUser) GetEmail() string              { return u.email }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey { return u.privateKey }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.reg }
func (u *acmeUser) SetRegistration(r *registration.Resource) { u.reg = r }
