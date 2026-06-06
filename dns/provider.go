// Package dns provides a generic DNS provider interface and implementations
// for any DNS provider supported by the go-acme/lego library.
package dns

import (
	"context"
	"fmt"
	"sync"
)

// Provider is the generic DNS provider interface. Any DNS provider supported
// by lego can implement this interface to be used by the plugin.
type Provider interface {
	// Present creates a DNS TXT record for the given domain and token
	// to fulfill the ACME DNS-01 challenge.
	Present(ctx context.Context, domain, token, keyAuth string) error

	// CleanUp removes the DNS TXT record used for the challenge.
	CleanUp(ctx context.Context, domain, token, keyAuth string) error

	// Name returns the name of the DNS provider (e.g., "aws", "cloudflare", "route53").
	Name() string
}

// ProviderFactory is used to create DNS provider instances from credentials.
// This allows the plugin to support any lego-compatible DNS provider without
// hardcoding provider-specific logic.
type ProviderFactory interface {
	// NewProvider creates a new DNS provider instance from the given configuration.
	NewProvider(config map[string]interface{}) (Provider, error)
}

// ProviderRegistry maintains a registry of DNS provider factories.
// This is the central registry that allows the plugin to support any
// lego-compatible DNS provider.
type ProviderRegistry struct {
	mu      sync.RWMutex
	factories map[string]ProviderFactory
}

// NewProviderRegistry creates a new provider registry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		factories: make(map[string]ProviderFactory),
	}
}

// Register adds a new DNS provider factory to the registry.
func (r *ProviderRegistry) Register(name string, factory ProviderFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[name] = factory
}

// GetProvider creates a new DNS provider instance for the given name and credentials.
func (r *ProviderRegistry) GetProvider(name string, creds map[string]interface{}) (Provider, error) {
	r.mu.RLock()
	factory, ok := r.factories[name]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown DNS provider: %s", name)
	}
	return factory.NewProvider(creds)
}

// GetFactory returns the factory for a DNS provider by name.
func (r *ProviderRegistry) GetFactory(name string) (ProviderFactory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	factory, ok := r.factories[name]
	if !ok {
		return nil, fmt.Errorf("unknown DNS provider: %s", name)
	}
	return factory, nil
}

// ValidateProvider checks if a provider name is registered without creating an instance.
// This allows storing roles with incomplete credentials — validation happens at enrollment time.
func (r *ProviderRegistry) ValidateProvider(name string) error {
	r.mu.RLock()
	_, ok := r.factories[name]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("unknown DNS provider: %s", name)
	}
	return nil
}

// ListProviders returns a list of all registered provider names.
func (r *ProviderRegistry) ListProviders() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}
