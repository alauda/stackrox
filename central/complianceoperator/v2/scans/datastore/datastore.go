package datastore

import (
	"context"
	"testing"

	pgStore "github.com/stackrox/rox/central/complianceoperator/v2/scans/store/postgres"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
)

// DataStore is the entry point for storing/retrieving compliance operator scan objects.
//
//go:generate mockgen-wrapper
type DataStore interface {
	// GetScanObject adds the rule to the database
	GetScanObject(ctx context.Context, id string) (*storage.ComplianceOperatorScanV2, bool, error)

	// UpsertScanObject adds the scan object to the database
	UpsertScanObject(ctx context.Context, result *storage.ComplianceOperatorScanV2) error

	// DeleteScanObject removes a scan object from the database
	DeleteScanObject(ctx context.Context, id string) error

	// GetScanObjectByCluster retrieves scan objects by cluster
	GetScanObjectByCluster(ctx context.Context, clusterID string) ([]*storage.ComplianceOperatorScanV2, error)
}

// New returns an instance of DataStore.
func New(complianceScanObjectStorage pgStore.Store) DataStore {
	ds := &datastoreImpl{
		store: complianceScanObjectStorage,
	}
	return ds
}

// GetTestPostgresDataStore provides a datastore connected to postgres for testing purposes.
func GetTestPostgresDataStore(_ *testing.T, pool postgres.DB) (DataStore, error) {
	store := pgStore.New(pool)
	return New(store), nil
}
