package storage

import (
	"context"
	"strings"
)

// OpenBaoStorage wraps an OpenBao plugin SDK storage View.
// This interface is satisfied by both the OpenBao and Vault SDK storage.View types.
type OpenBaoStorage struct {
	view StorageView
}

// StorageView is a minimal interface matching storage.View from the OpenBao/Vault SDK.
type StorageView interface {
	List() ([]string, error)
	Get(key string) ([]byte, error)
	Put(key string, value []byte) error
	Delete(key string) error
}

// NewOpenBaoStorage creates a new storage wrapper from a StorageView.
func NewOpenBaoStorage(view StorageView) *OpenBaoStorage {
	return &OpenBaoStorage{view: view}
}

// Put stores a key-value pair.
func (s *OpenBaoStorage) Put(ctx context.Context, key string, value []byte) error {
	return s.view.Put(key, value)
}

// Get retrieves a value by key.
func (s *OpenBaoStorage) Get(ctx context.Context, key string) ([]byte, error) {
	value, err := s.view.Get(key)
	if err != nil {
		return nil, &NotFoundError{Key: key}
	}
	if value == nil {
		return nil, &NotFoundError{Key: key}
	}
	return value, nil
}

// Delete removes a key.
func (s *OpenBaoStorage) Delete(ctx context.Context, key string) error {
	return s.view.Delete(key)
}

// List returns all keys matching a prefix.
func (s *OpenBaoStorage) List(ctx context.Context, prefix string) ([]string, error) {
	keys, err := s.view.List()
	if err != nil {
		return nil, err
	}

	var result []string
	for _, key := range keys {
		if strings.HasPrefix(key, prefix) {
			result = append(result, key)
		}
	}
	return result, nil
}
