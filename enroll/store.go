package enroll

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openbao/dnsacme/storage"
)

// EnrollmentStorage wraps storage.Backend with enrollment-specific methods.
type EnrollmentStorage struct {
	backend storage.StorageBackend
}

// NewEnrollmentStorage creates a new enrollment storage wrapper.
func NewEnrollmentStorage(backend storage.StorageBackend) *EnrollmentStorage {
	return &EnrollmentStorage{backend: backend}
}

const enrollmentPrefix = "enroll/"

// CreateEnrollment creates a new enrollment state in storage.
func (s *EnrollmentStorage) CreateEnrollment(ctx context.Context, state *EnrollmentState) error {
	key := enrollmentPrefix + state.ID
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal enrollment state: %w", err)
	}
	return s.backend.Put(ctx, key, data)
}

// GetEnrollment retrieves an enrollment state from storage.
func (s *EnrollmentStorage) GetEnrollment(ctx context.Context, id string) (*EnrollmentState, error) {
	key := enrollmentPrefix + id
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
	return storage.NewConfigStorage(s.backend).GetACMEAccount(ctx)
}

// GetACMEKey retrieves the ACME private key PEM data.
func (s *EnrollmentStorage) GetACMEKey(ctx context.Context) (string, error) {
	account, err := s.GetACMEAccount(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get ACME account: %w", err)
	}
	return account.Key, nil
}
