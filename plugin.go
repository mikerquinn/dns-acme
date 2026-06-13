// Package main implements the OpenBao DNS-01 ACME plugin.
package main

import (
	"context"
	"sync"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/hashicorp/go-hclog"
	"github.com/mikerquinn/dns-acme/dns"
	"github.com/mikerquinn/dns-acme/enroll"
	"github.com/mikerquinn/dns-acme/storage"
)

// Plugin is the main plugin struct containing all shared state.
type Plugin struct {
	logger hclog.Logger

	// DNS provider registry (generic, supports any lego provider)
	registry *dns.ProviderRegistry

	// Storage backends
	configStore *storage.ConfigStorage
	enrollStore *enroll.EnrollmentStorage

	// ACME account state (lazy-loaded from storage)
	acmeEmail  string
	acmeKeyPEM string
	acmeURL    string

	// Issuer
	issuer *enroll.Issuer

	// Lock for ACME operations and client recreation
	mu sync.RWMutex
}

// NewPlugin creates a new plugin instance.
func NewPlugin(logger hclog.Logger) *Plugin {
	return &Plugin{
		logger:   logger,
		registry: dns.NewProviderRegistry(),
	}
}

// Init sets up the plugin with storage and issuer.
func (p *Plugin) Init(ctx context.Context, backend storage.StorageBackend) {
	p.configStore = storage.NewConfigStorage(backend)
	p.enrollStore = enroll.NewEnrollmentStorage(backend)

	// Try to load ACME account from storage
	account, err := p.configStore.GetACMEAccount(ctx)
	if err == nil {
		p.acmeEmail = account.Email
		p.acmeKeyPEM = account.Key
		p.logger.Info("loaded ACME account from storage")
	}

	p.issuer = enroll.NewIssuer(p.enrollStore, p.registry)
}

// reset clears all cached state (used by Invalidate callback).
func (p *Plugin) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.acmeEmail = ""
	p.acmeKeyPEM = ""
	p.acmeURL = ""
}

// acmeClient builds a lego ACME client from stored configuration.
func (p *Plugin) acmeClient(ctx context.Context) (*lego.Client, error) {
	p.mu.RLock()
	email := p.acmeEmail
	keyPEM := p.acmeKeyPEM
	url := p.acmeURL
	p.mu.RUnlock()

	if email == "" || keyPEM == "" {
		// Lazy load from config store
		if p.configStore == nil {
			return nil, nil
		}
		account, err := p.configStore.GetACMEAccount(ctx)
		if err != nil {
			return nil, nil
		}
		email = account.Email
		keyPEM = account.Key
	}

	if email == "" || keyPEM == "" {
		return nil, nil
	}

	key, err := parseKey([]byte(keyPEM))
	if err != nil {
		return nil, err
	}

	user := &acmeUser{email: email, privateKey: key, reg: nil}

	if url == "" {
		url = defaultACMEURL
	}

	config := lego.NewConfig(user)
	config.CADirURL = url
	config.Certificate.KeyType = certcrypto.RSA2048
	config.UserAgent = "openbao-dnsacme-plugin"

	return lego.NewClient(config)
}
