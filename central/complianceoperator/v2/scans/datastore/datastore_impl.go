package datastore

import (
	"context"

	"github.com/stackrox/rox/central/complianceoperator/v2/scans/store/postgres"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/sac/resources"
	"github.com/stackrox/rox/pkg/search"
)

var (
	complianceOperatorSAC = sac.ForResource(resources.ComplianceOperator)
)

type datastoreImpl struct {
	store postgres.Store
}

// GetScanObject retrieves the scan object from the database
func (d *datastoreImpl) GetScanObject(ctx context.Context, id string) (*storage.ComplianceOperatorScanV2, bool, error) {
	if ok, err := complianceOperatorSAC.ReadAllowed(ctx); err != nil {
		return nil, false, err
	} else if !ok {
		return nil, false, sac.ErrResourceAccessDenied
	}

	return d.store.Get(ctx, id)
}

// UpsertScanObject adds the scan object to the database
func (d *datastoreImpl) UpsertScanObject(ctx context.Context, scanObject *storage.ComplianceOperatorScanV2) error {
	if ok, err := complianceOperatorSAC.WriteAllowed(ctx); err != nil {
		return err
	} else if !ok {
		return sac.ErrResourceAccessDenied
	}

	return d.store.Upsert(ctx, scanObject)
}

// DeleteScanObject removes a scan object from the database
func (d *datastoreImpl) DeleteScanObject(ctx context.Context, id string) error {
	if ok, err := complianceOperatorSAC.WriteAllowed(ctx); err != nil {
		return err
	} else if !ok {
		return sac.ErrResourceAccessDenied
	}

	return d.store.Delete(ctx, id)
}

// GetScanObjectByCluster retrieves scan objects by cluster
func (d *datastoreImpl) GetScanObjectByCluster(ctx context.Context, clusterID string) ([]*storage.ComplianceOperatorScanV2, error) {
	if ok, err := complianceOperatorSAC.ReadAllowed(ctx); err != nil {
		return nil, err
	} else if !ok {
		return nil, sac.ErrResourceAccessDenied
	}

	return d.store.GetByQuery(ctx, search.NewQueryBuilder().
		AddExactMatches(search.ClusterID, clusterID).ProtoQuery())
}
