package store

import (
	"github.com/stackrox/rox/generated/storage"
)

// Store provides storage functionality for active component.
//go:generate mockgen-wrapper
type Store interface {
	Exists(id string) (bool, error)
	Get(id string) (*storage.ActiveComponent, bool, error)
	GetBatch(ids []string) ([]*storage.ActiveComponent, []int, error)
}
