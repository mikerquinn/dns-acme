// Package main implements the OpenBao DNS-01 ACME plugin.
package main

import (
	"context"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/sdk/v2/logical"
	pb "github.com/openbao/openbao/sdk/v2/plugin"
	"github.com/openbao/dnsacme/dns"
	"github.com/openbao/dnsacme/enroll"
	"github.com/openbao/dnsacme/storage"
)

// --- Plugin implementation ---

// Plugin is the main plugin struct containing all state.
type Plugin struct {
	logger hclog.Logger

	// DNS provider registry (generic, supports any lego provider)
	registry *dns.ProviderRegistry

	// Storage backends
	configStore *storage.ConfigStorage
	enrollStore *enroll.EnrollmentStorage

	// ACME state
	acmeEmail  string
	acmeKeyPEM string
	acmeURL    string

	// Issuer
	issuer *enroll.Issuer

	// Lock for ACME operations
	mu sync.Mutex
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
	if backend == nil {
		p.logger.Warn("Init called with nil backend, using memory storage")
		backend = &memoryBackend{}
	}
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

// memoryBackend is a minimal in-memory fallback for when OpenBao storage is not yet available.
type memoryBackend struct{}

func (*memoryBackend) Put(ctx context.Context, key string, value []byte) error            { return nil }
func (*memoryBackend) Get(ctx context.Context, key string) ([]byte, error)                { return nil, &storage.NotFoundError{Key: key} }
func (*memoryBackend) Delete(ctx context.Context, key string) error                       { return nil }
func (*memoryBackend) List(ctx context.Context, prefix string) ([]string, error)          { return nil, nil }

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:       "dnsacme",
		Level:      hclog.Trace,
		Output:     hclog.DefaultOutput,
		JSONFormat: true,
	})

	logger.Info("DNS-01 ACME plugin starting in native plugin mode")
	impl := buildPlugin(logger)
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: plugin.HandshakeConfig{
			MagicCookieKey:   "VAULT_BACKEND_PLUGIN",
			MagicCookieValue: "6669da05-b1c8-4f49-97d9-c8e5bed98e20",
		},
		VersionedPlugins: map[int]plugin.PluginSet{
			3: {
				"backend": &pb.GRPCBackendPlugin{
					Factory: func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
						if impl.configStore == nil {
							impl.Init(ctx, &openbaoStorageView{storage: config.StorageView})
						}
						return &dnsacmeBackend{Plugin: impl, logger: logger}, nil
					},
					Logger: logger,
				},
			},
			4: {
				"backend": &pb.GRPCBackendPlugin{
					Factory: func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
						if impl.configStore == nil {
							impl.Init(ctx, &openbaoStorageView{storage: config.StorageView})
						}
						return &dnsacmeBackend{Plugin: impl, logger: logger}, nil
					},
					Logger: logger,
				},
			},
			5: {
				"backend": &pb.GRPCBackendPlugin{
					Factory: func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
						if impl.configStore == nil {
							impl.Init(ctx, &openbaoStorageView{storage: config.StorageView})
						}
						return &dnsacmeBackend{Plugin: impl, logger: logger}, nil
					},
					Logger: logger,
				},
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

func buildPlugin(logger hclog.Logger) *Plugin {
	impl := NewPlugin(logger)

	// Register the lego provider factory under all known lego provider names.
	// This allows any lego-supported DNS provider (cloudflare, route53, etc.)
	// to be used by referencing the provider name in the role config.
	factory := &dns.LegoProviderFactory{}
	for _, name := range dns.ListSupportedProviders() {
		impl.registry.Register(name, factory)
	}

	// Store logger reference for backend use
	impl.logger = logger

	return impl
}
