// This file was originally generated with
// //go:generate cp ../../../../central/networkgraph/flow/datastore/internal/store/postgres/cluster_impl.go .

package postgres

import (
	"context"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/migrator/migrations/n_30_to_n_31_postgres_network_flows/store"
	"github.com/stackrox/rox/pkg/transitional/protocompat/types"
	"github.com/stackrox/rox/pkg/utils"
)

// NewClusterStore returns a new ClusterStore instance using the provided rocksdb instance.
func NewClusterStore(db *pgxpool.Pool) store.ClusterStore {
	return &clusterStoreImpl{
		db: db,
	}
}

type clusterStoreImpl struct {
	db *pgxpool.Pool
}

// GetFlowStore returns the FlowStore for the cluster ID, or nil if none exists.
func (s *clusterStoreImpl) GetFlowStore(clusterID string) store.FlowStore {
	return &flowStoreImpl{
		db:        s.db,
		clusterID: clusterID,
	}
}

// CreateFlowStore returns the FlowStore for the cluster ID, or creates one if none exists.
func (s *clusterStoreImpl) CreateFlowStore(_ context.Context, clusterID string) store.FlowStore {
	return New(s.db, clusterID)
}

// Walk is a stub for satisfying interfaces
func (s *clusterStoreImpl) Walk(_ context.Context, _ func(clusterID string, _ types.Timestamp, _ []*storage.NetworkFlow) error) error {
	utils.CrashOnError(errors.New("Unexpected call to stub interface"))
	return nil
}
