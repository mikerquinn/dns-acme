// Package storage provides configuration storage for the plugin.
package storage

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
)

const (
	configKeyACMEEmail = "config/acme_email"
	configKeyACMEKey   = "config/acme_key"
	configKeyACMEURL   = "config/acme_url"
	configKeyACMEURI   = "config/acme_uri"
)

// ACMEAccount stores the ACME account configuration.
type ACMEAccount struct {
	Email string `json:"email"`
	Key   string `json:"key"`
	URL   string `json:"url"`
	URI   string `json:"uri"`
}

// DNSRole stores DNS provider configuration for a role.
type DNSRole struct {
	Name        string                 `json:"name"`
	Provider    string                 `json:"provider"`
	Credentials map[string]interface{} `json:"credentials"`
	Zone        string                 `json:"zone"`
}

// ConfigStorage wraps StorageBackend with configuration-specific methods.
type ConfigStorage struct {
	backend StorageBackend
	logger  hclog.Logger
}

// NewConfigStorage creates a new config storage wrapper.
func NewConfigStorage(backend StorageBackend, logger hclog.Logger) *ConfigStorage {
	return &ConfigStorage{backend: backend, logger: logger}
}

// Backend returns the underlying storage backend for debugging.
func (s *ConfigStorage) Backend() StorageBackend { return s.backend }

// GetACMEAccount retrieves the ACME account configuration.
func (s *ConfigStorage) GetACMEAccount(ctx context.Context) (*ACMEAccount, error) {
	s.logger.Info("configStore.GetACMEAccount", "backend", fmt.Sprintf("%T", s.Backend()))
	emailData, err := s.backend.Get(ctx, configKeyACMEEmail)
	if err != nil {
		return nil, fmt.Errorf("failed to get ACME email: %w", err)
	}

	keyData, err := s.backend.Get(ctx, configKeyACMEKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get ACME key: %w", err)
	}

	var account ACMEAccount
	account.Email = string(emailData)
	account.Key = string(keyData)

	urlData, err := s.backend.Get(ctx, configKeyACMEURL)
	if err == nil && len(urlData) > 0 {
		account.URL = string(urlData)
	}

	uriData, err := s.backend.Get(ctx, configKeyACMEURI)
	if err == nil && len(uriData) > 0 {
		account.URI = string(uriData)
	}

	s.logger.Info("configStore.GetACMEAccount", "email", account.Email, "key_prefix", account.Key[:30], "uri", account.URI)
	return &account, nil
}

// SetACMEAccount stores the ACME account configuration.
func (s *ConfigStorage) SetACMEAccount(ctx context.Context, account *ACMEAccount) error {
	if s.logger != nil {
		s.logger.Info("configStore.SetACMEAccount", "email", account.Email, "key_prefix", account.Key[:30], "uri", account.URI)
	}
	if err := s.backend.Put(ctx, configKeyACMEEmail, []byte(account.Email)); err != nil {
		return fmt.Errorf("failed to set ACME email: %w", err)
	}
	if err := s.backend.Put(ctx, configKeyACMEKey, []byte(account.Key)); err != nil {
		return fmt.Errorf("failed to set ACME key: %w", err)
	}
	if account.URL != "" {
		if err := s.backend.Put(ctx, configKeyACMEURL, []byte(account.URL)); err != nil {
			return fmt.Errorf("failed to set ACME URL: %w", err)
		}
	} else {
		s.backend.Delete(ctx, configKeyACMEURL)
	}
	if account.URI != "" {
		if err := s.backend.Put(ctx, configKeyACMEURI, []byte(account.URI)); err != nil {
			return fmt.Errorf("failed to set ACME URI: %w", err)
		}
	} else {
		s.backend.Delete(ctx, configKeyACMEURI)
	}
	return nil
}
