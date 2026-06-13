// Package storage provides configuration storage for the plugin.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
)

const (
	configKeyACMEEmail = "config/acme_email"
	configKeyACMEKey   = "config/acme_key"
	configKeyACMEURL   = "config/acme_url"
)

// ACMEAccount stores the ACME account configuration.
type ACMEAccount struct {
	Email string `json:"email"`
	Key   string `json:"key"`
	URL   string `json:"url"`
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
}

// NewConfigStorage creates a new config storage wrapper.
func NewConfigStorage(backend StorageBackend) *ConfigStorage {
	return &ConfigStorage{backend: backend}
}

// GetACMEAccount retrieves the ACME account configuration.
func (s *ConfigStorage) GetACMEAccount(ctx context.Context) (*ACMEAccount, error) {
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

	return &account, nil
}

// SetACMEAccount stores the ACME account configuration.
func (s *ConfigStorage) SetACMEAccount(ctx context.Context, account *ACMEAccount) error {
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
	}
	return nil
}

// ListRoles returns all DNS role names.
func (s *ConfigStorage) ListRoles(ctx context.Context) ([]string, error) {
	keys, err := s.backend.List(ctx, "config/role/")
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	var roles []string
	for _, key := range keys {
		if key != "" {
			roles = append(roles, key)
		}
	}

	return roles, nil
}

// GetRole retrieves a DNS role by name.
func (s *ConfigStorage) GetRole(ctx context.Context, name string) (*DNSRole, error) {
	key := "config/role/" + name
	data, err := s.backend.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get role %s: %w", name, err)
	}

	var role DNSRole
	if err := json.Unmarshal(data, &role); err != nil {
		return nil, fmt.Errorf("failed to unmarshal role %s: %w", name, err)
	}

	return &role, nil
}

// SetRole stores a DNS role.
func (s *ConfigStorage) SetRole(ctx context.Context, role *DNSRole) error {
	key := "config/role/" + role.Name
	data, err := json.Marshal(role)
	if err != nil {
		return fmt.Errorf("failed to marshal role: %w", err)
	}
	return s.backend.Put(ctx, key, data)
}

// DeleteRole removes a DNS role.
func (s *ConfigStorage) DeleteRole(ctx context.Context, name string) error {
	return s.backend.Delete(ctx, "config/role/"+name)
}
