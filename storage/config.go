// Package storage provides configuration storage for the plugin.
package storage

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/go-hclog"
)

const (
	ConfigKeyACMEEmail = "config/acme_email"
	ConfigKeyACMEKey   = "config/acme_key"
	ConfigKeyACMEURL   = "config/acme_url"
	ConfigKeyACMEURI   = "config/acme_uri"
	ConfigKeyRoles     = "config/role/"
)

// min returns the smaller of a or b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

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

// DeleteACMEAccount removes all ACME account data from storage.
func (s *ConfigStorage) DeleteACMEAccount(ctx context.Context) error {
	var errs []string
	if err := s.backend.Delete(ctx, ConfigKeyACMEEmail); err != nil {
		errs = append(errs, fmt.Sprintf("email: %v", err))
	}
	if err := s.backend.Delete(ctx, ConfigKeyACMEKey); err != nil {
		errs = append(errs, fmt.Sprintf("key: %v", err))
	}
	if err := s.backend.Delete(ctx, ConfigKeyACMEURL); err != nil {
		errs = append(errs, fmt.Sprintf("url: %v", err))
	}
	if err := s.backend.Delete(ctx, ConfigKeyACMEURI); err != nil {
		errs = append(errs, fmt.Sprintf("uri: %v", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to delete some ACME account keys: %s", strings.Join(errs, ", "))
	}
	return nil
}

// Backend returns the underlying storage backend for debugging.
func (s *ConfigStorage) Backend() StorageBackend { return s.backend }

// GetACMEAccount retrieves the ACME account configuration.
func (s *ConfigStorage) GetACMEAccount(ctx context.Context) (*ACMEAccount, error) {
	s.logger.Info("configStore.GetACMEAccount", "backend", fmt.Sprintf("%T", s.Backend()), "configStore_ptr", fmt.Sprintf("%p", s), "backend_ptr", fmt.Sprintf("%p", s.Backend()))
	// List all keys to debug
	keys, listErr := s.backend.List(ctx, "config/")
	s.logger.Info("configStore.GetACMEAccount: listing config/", "keys", keys, "listErr", listErr)
	emailData, err := s.backend.Get(ctx, ConfigKeyACMEEmail)
	s.logger.Info("configStore.GetACMEAccount: got email", "key", ConfigKeyACMEEmail, "err", err, "len", len(emailData), "backend_ptr", fmt.Sprintf("%p", s.Backend()))
	if err != nil {
		return nil, fmt.Errorf("failed to get ACME email: %w", err)
	}

	keyData, err := s.backend.Get(ctx, ConfigKeyACMEKey)
	s.logger.Info("configStore.GetACMEAccount: got key", "err", err, "len", len(keyData))
	if err != nil {
		return nil, fmt.Errorf("failed to get ACME key: %w", err)
	}

	var account ACMEAccount
	account.Email = string(emailData)
	account.Key = string(keyData)

	urlData, err := s.backend.Get(ctx, ConfigKeyACMEURL)
	if err == nil && len(urlData) > 0 {
		account.URL = string(urlData)
	}

	uriData, err := s.backend.Get(ctx, ConfigKeyACMEURI)
	if err == nil && len(uriData) > 0 {
		account.URI = string(uriData)
	}

	keyPrefix := account.Key[:min(30, len(account.Key))]
	s.logger.Info("configStore.GetACMEAccount", "email", account.Email, "key_prefix", keyPrefix, "uri", account.URI)
	return &account, nil
}

// SetACMEAccount stores the ACME account configuration.
func (s *ConfigStorage) SetACMEAccount(ctx context.Context, account *ACMEAccount) error {
	if s.logger != nil {
		keyPrefix := account.Key[:min(30, len(account.Key))]
		s.logger.Info("configStore.SetACMEAccount", "email", account.Email, "key_prefix", keyPrefix, "uri", account.URI, "backend_type", fmt.Sprintf("%T", s.Backend()))
	}
	s.logger.Info("configStore.SetACMEAccount: about to put email", "key", ConfigKeyACMEEmail, "backend_ptr", fmt.Sprintf("%p", s.Backend()))
	if err := s.backend.Put(ctx, ConfigKeyACMEEmail, []byte(account.Email)); err != nil {
		return fmt.Errorf("failed to set ACME email: %w", err)
	}
	s.logger.Info("configStore.SetACMEAccount: email put succeeded", "key", ConfigKeyACMEEmail)
	// Verify the put worked - use a FRESH Get on the same backend
	verify, err := s.backend.Get(ctx, ConfigKeyACMEEmail)
	s.logger.Info("configStore.SetACMEAccount: verify email", "len", len(verify), "err", err, "verify_value", string(verify))
	// Also list keys to see what exists
	keys, listErr := s.backend.List(ctx, "config/")
	s.logger.Info("configStore.SetACMEAccount: listing config/", "keys", keys, "listErr", listErr)
	if err != nil {
		s.logger.Info("configStore.SetACMEAccount: verify FAILED", "err", err)
	}
	if err := s.backend.Put(ctx, ConfigKeyACMEKey, []byte(account.Key)); err != nil {
		return fmt.Errorf("failed to set ACME key: %w", err)
	}
	if account.URL != "" {
		if err := s.backend.Put(ctx, ConfigKeyACMEURL, []byte(account.URL)); err != nil {
			return fmt.Errorf("failed to set ACME URL: %w", err)
		}
	} else {
		s.backend.Delete(ctx, ConfigKeyACMEURL)
	}
	if account.URI != "" {
		if err := s.backend.Put(ctx, ConfigKeyACMEURI, []byte(account.URI)); err != nil {
			return fmt.Errorf("failed to set ACME URI: %w", err)
		}
	} else {
		s.backend.Delete(ctx, ConfigKeyACMEURI)
	}
	return nil
}

// MaskSensitiveCredentials returns a copy of credentials with sensitive values masked.
func MaskSensitiveCredentials(creds map[string]interface{}) map[string]interface{} {
	sensitiveKeys := map[string]bool{
		"key": true, "secret": true, "token": true, "password": true,
		"api_key": true, "api_token": true, "access_key": true,
		"secret_key": true, "private_key": true,
		"dns_api_token": true, "access_token": true,
	}
	masked := make(map[string]interface{}, len(creds))
	for k, v := range creds {
		lower := strings.ToLower(k)
		// Exact match or key ends with _TOKEN/_KEY/_SECRET/_PASSWORD
		if sensitiveKeys[lower] || strings.HasSuffix(lower, "_token") ||
			strings.HasSuffix(lower, "_key") || strings.HasSuffix(lower, "_secret") ||
			strings.HasSuffix(lower, "_password") {
			masked[k] = "***"
		} else {
			masked[k] = v
		}
	}
	return masked
}
