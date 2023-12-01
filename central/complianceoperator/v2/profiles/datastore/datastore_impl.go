package datastore

import (
	"context"

	"github.com/pkg/errors"
	edge "github.com/stackrox/rox/central/complianceoperator/v2/profiles/profileclusteredge/store/postgres"
	pgStore "github.com/stackrox/rox/central/complianceoperator/v2/profiles/store/postgres"
	"github.com/stackrox/rox/generated/storage"
	pgPkg "github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/sac/resources"
	"github.com/stackrox/rox/pkg/search"
	"github.com/stackrox/rox/pkg/uuid"
)

var (
	complianceOperatorSAC = sac.ForResource(resources.ComplianceOperator)
)

type datastoreImpl struct {
	db               pgPkg.DB
	store            pgStore.Store
	profileEdgeStore edge.Store
}

// UpsertProfile adds the profile to the database
func (d *datastoreImpl) UpsertProfile(ctx context.Context, profile *storage.ComplianceOperatorProfileV2, clusterID string, profileUID string) error {
	if ok, err := complianceOperatorSAC.WriteAllowed(ctx); err != nil {
		return err
	} else if !ok {
		return sac.ErrResourceAccessDenied
	}

	tx, err := d.db.Begin(ctx)
	if err != nil {
		return err
	}
	ctx = pgPkg.ContextWithTx(ctx, tx)

	if err := d.store.Upsert(ctx, profile); err != nil {
		return wrapRollback(ctx, tx, errors.Wrapf(err, "error adding profile %s", profile.GetProfileId()))
	}

	profileEdge := &storage.ComplianceOperatorProfileClusterEdge{
		Id:         uuid.NewV4().String(),
		ProfileId:  profile.GetId(),
		ProfileUid: profileUID,
		ClusterId:  clusterID,
	}

	err = d.profileEdgeStore.Upsert(ctx, profileEdge)
	if err != nil {
		return wrapRollback(ctx, tx, errors.Wrapf(err, "error adding profile for cluster %s", clusterID))
	}

	err = tx.Commit(ctx)
	if err != nil {
		return wrapRollback(ctx, tx, errors.Wrapf(err, "error adding profile for cluster %s", clusterID))
	}
	return nil
}

// DeleteProfileForCluster removes a profile from the database
func (d *datastoreImpl) DeleteProfileForCluster(ctx context.Context, uid string, clusterID string) error {
	if ok, err := complianceOperatorSAC.WriteAllowed(ctx); err != nil {
		return err
	} else if !ok {
		return sac.ErrResourceAccessDenied
	}

	return d.profileEdgeStore.DeleteByQuery(ctx, search.NewQueryBuilder().
		AddExactMatches(search.ClusterID, clusterID).
		AddExactMatches(search.ComplianceOperatorProfileUID, uid).ProtoQuery())
}

// GetProfileEdgesByCluster gets the list of profile edges for a given cluster
func (d *datastoreImpl) GetProfileEdgesByCluster(ctx context.Context, clusterID string) ([]*storage.ComplianceOperatorProfileClusterEdge, error) {
	if ok, err := complianceOperatorSAC.ReadAllowed(ctx); err != nil {
		return nil, err
	} else if !ok {
		return nil, sac.ErrResourceAccessDenied
	}

	return d.profileEdgeStore.GetByQuery(ctx, search.NewQueryBuilder().
		AddExactMatches(search.ClusterID, clusterID).ProtoQuery())
}

func wrapRollback(ctx context.Context, tx *pgPkg.Tx, err error) error {
	rollbackErr := tx.Rollback(ctx)
	if rollbackErr != nil {
		return errors.Wrapf(rollbackErr, "rolling back due to err: %v", err)
	}
	return err
}
