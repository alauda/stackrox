package datastore

import (
	"context"

	graphConfigDS "github.com/stackrox/rox/central/networkgraph/config/datastore"
	networkEntityDS "github.com/stackrox/rox/central/networkgraph/entity/datastore"
	"github.com/stackrox/rox/central/networkgraph/flow/datastore/internal/store"
	"github.com/stackrox/rox/pkg/expiringcache"
)

// ClusterDataStore stores the network edges per cluster.
//go:generate mockgen-wrapper
type ClusterDataStore interface {
	GetFlowStore(ctx context.Context, clusterID string) (FlowDataStore, error)
	CreateFlowStore(ctx context.Context, clusterID string) (FlowDataStore, error)
}

// NewClusterDataStore returns a new instance of ClusterDataStore using the input storage underneath.
func NewClusterDataStore(storage store.ClusterStore, graphConfig graphConfigDS.DataStore, networkEntities networkEntityDS.EntityDataStore, deletedDeploymentsCache expiringcache.Cache) ClusterDataStore {
	return &clusterDataStoreImpl{
		storage:                 storage,
		graphConfig:             graphConfig,
		networkEntities:         networkEntities,
		deletedDeploymentsCache: deletedDeploymentsCache,
	}
}
