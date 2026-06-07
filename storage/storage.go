// Package storage provides storage interfaces backed by OpenBao's storage.
package storage

import (
	"context"
)

// StorageBackend is the interface for storage operations.
// This is satisfied by both our in-memory backend and the OpenBao plugin SDK storage.View.
type StorageBackend interface {
	Put(ctx context.Context, key string, value []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// NotFoundError is returned when a key is not found in storage.
type NotFoundError struct {
	Key string
}

func (e *NotFoundError) Error() string {
	return "key not found: " + e.Key
}
