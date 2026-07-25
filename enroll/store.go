package enroll

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/mikerquinn/dns-acme/storage"
)

// EnrollmentStorage wraps storage.Backend with enrollment-specific methods.
type EnrollmentStorage struct {
	backend     storage.StorageBackend
	configStore *storage.ConfigStorage
	logger      hclog.Logger
}

// NewEnrollmentStorage creates a new enrollment storage wrapper.
func NewEnrollmentStorage(backend storage.StorageBackend, configStore *storage.ConfigStorage, logger hclog.Logger) *EnrollmentStorage {
	return &EnrollmentStorage{backend: backend, configStore: configStore, logger: logger}
}

const enrollmentPrefix = "enroll/"

// CreateEnrollment creates a new enrollment state in storage.
func (s *EnrollmentStorage) CreateEnrollment(ctx context.Context, state *EnrollmentState) error {
	key := enrollmentPrefix + state.ID
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal enrollment state: %w", err)
	}
	s.logger.Info("CreateEnrollment: about to put", "key", key, "configStore_ptr", fmt.Sprintf("%p", s.configStore))
	err = s.backend.Put(ctx, key, data)
	s.logger.Info("CreateEnrollment: put result", "key", key, "err", err)
	// Verify
	verify, err2 := s.backend.Get(ctx, key)
	s.logger.Info("CreateEnrollment: verify", "key", key, "len", len(verify), "err", err2)
	return err
}

// GetEnrollment retrieves an enrollment state from storage.
func (s *EnrollmentStorage) GetEnrollment(ctx context.Context, id string) (*EnrollmentState, error) {
	key := enrollmentPrefix + id
	s.logger.Info("GetEnrollment: about to get", "key", key, "backend_ptr", fmt.Sprintf("%p", s.backend), "configStore_backend_ptr", fmt.Sprintf("%p", s.configStore.Backend()))
	data, err := s.backend.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get enrollment: %w", err)
	}

	var state EnrollmentState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal enrollment state: %w", err)
	}

	return &state, nil
}

// UpdateEnrollment updates an enrollment state in storage.
func (s *EnrollmentStorage) UpdateEnrollment(ctx context.Context, state *EnrollmentState) error {
	key := enrollmentPrefix + state.ID
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal enrollment state: %w", err)
	}
	return s.backend.Put(ctx, key, data)
}

// GetACMEAccount retrieves the ACME account configuration.
func (s *EnrollmentStorage) GetACMEAccount(ctx context.Context) (*storage.ACMEAccount, error) {
	s.logger.Info("EnrollmentStorage.GetACMEAccount: delegating", "configStore_ptr", fmt.Sprintf("%p", s.configStore), "backend_ptr", fmt.Sprintf("%p", s.configStore.Backend()))
	return s.configStore.GetACMEAccount(ctx)
}

// SetACMEAccount stores the ACME account configuration.
func (s *EnrollmentStorage) SetACMEAccount(ctx context.Context, account *storage.ACMEAccount) error {
	return s.configStore.SetACMEAccount(ctx, account)
}

// GetACMEKey retrieves the ACME private key PEM data.
func (s *EnrollmentStorage) GetACMEKey(ctx context.Context) (string, error) {
	account, err := s.GetACMEAccount(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get ACME account: %w", err)
	}
	return account.Key, nil
}

// GetRole retrieves a DNS role from storage by name.
func (s *EnrollmentStorage) GetRole(ctx context.Context, name string) (*storage.DNSRole, error) {
	return storage.GetRole(ctx, s.backend, name)
}
