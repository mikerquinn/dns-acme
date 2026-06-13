package main

import (
	"context"

	"github.com/hashicorp/go-hclog"
	"github.com/mikerquinn/dns-acme/dns"
	pb "github.com/openbao/openbao/sdk/v2/plugin"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:       "dnsacme",
		Level:      hclog.Trace,
		Output:     hclog.DefaultOutput,
		JSONFormat: true,
	})

	logger.Info("DNS-01 ACME plugin starting in native plugin mode")

	// Build the plugin with registered providers
	impl := buildPlugin(logger)

	pb.ServeMultiplex(&pb.ServeOpts{
		BackendFactoryFunc: func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
			if impl.configStore == nil {
				impl.Init(ctx, &openbaoStorageView{storage: config.StorageView})
			}
			return &dnsacmeBackend{Plugin: impl, logger: logger}, nil
		},
		Logger: logger,
	})
}

// buildPlugin creates the plugin with all supported DNS providers registered.
func buildPlugin(logger hclog.Logger) *Plugin {
	impl := NewPlugin(logger)

	// Register the lego provider factory under all known lego provider names.
	// This allows any lego-supported DNS provider to be used by referencing
	// the provider name in the role config.
	factory := &dns.LegoProviderFactory{}
	for _, name := range dns.ListSupportedProviders() {
		impl.registry.Register(name, factory)
	}

	return impl
}

// openbaoStorageView wraps logical.Storage as StorageBackend.
type openbaoStorageView struct {
	storage logical.Storage
}

func (s *openbaoStorageView) Put(ctx context.Context, key string, value []byte) error {
	return s.storage.Put(ctx, &logical.StorageEntry{Key: key, Value: value})
}

func (s *openbaoStorageView) Get(ctx context.Context, key string) ([]byte, error) {
	entry, err := s.storage.Get(ctx, key)
	if err != nil || entry == nil {
		return nil, &storageNotFoundError{key: key}
	}
	return entry.Value, nil
}

func (s *openbaoStorageView) Delete(ctx context.Context, key string) error {
	return s.storage.Delete(ctx, key)
}

func (s *openbaoStorageView) List(ctx context.Context, prefix string) ([]string, error) {
	keys, err := s.storage.List(ctx, prefix)
	if err != nil {
		return nil, err
	}

	var result []string
	for _, key := range keys {
		if prefix == "" || len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			result = append(result, key)
		}
	}
	return result, nil
}

// storageNotFoundError is returned when a key is not found.
type storageNotFoundError struct {
	key string
}

func (e *storageNotFoundError) Error() string {
	return "key not found: " + e.key
}
