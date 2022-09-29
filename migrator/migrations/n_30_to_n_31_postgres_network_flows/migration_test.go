// Code originally generated by pg-bindings generator.

//go:build sql_integration
// +build sql_integration

package n30ton31

import (
	"context"
	"sort"
	"testing"

	"github.com/gogo/protobuf/types"
	"github.com/stackrox/rox/generated/storage"
	legacy "github.com/stackrox/rox/migrator/migrations/n_30_to_n_31_postgres_network_flows/legacy"
	pgStore "github.com/stackrox/rox/migrator/migrations/n_30_to_n_31_postgres_network_flows/postgres"
	"github.com/stackrox/rox/migrator/migrations/n_30_to_n_31_postgres_network_flows/store"
	pghelper "github.com/stackrox/rox/migrator/migrations/postgreshelper"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/rocksdb"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/testutils"
	"github.com/stackrox/rox/pkg/testutils/envisolator"
	"github.com/stackrox/rox/pkg/testutils/rocksdbtest"
	"github.com/stackrox/rox/pkg/timestamp"
	"github.com/stretchr/testify/suite"
)

func TestMigration(t *testing.T) {
	suite.Run(t, new(postgresMigrationSuite))
}

type postgresMigrationSuite struct {
	suite.Suite
	envIsolator *envisolator.EnvIsolator
	ctx         context.Context

	legacyDB   *rocksdb.RocksDB
	postgresDB *pghelper.TestPostgres
}

var _ suite.TearDownTestSuite = (*postgresMigrationSuite)(nil)

func (s *postgresMigrationSuite) SetupTest() {
	s.envIsolator = envisolator.NewEnvIsolator(s.T())
	s.envIsolator.Setenv(env.PostgresDatastoreEnabled.EnvVar(), "true")
	if !env.PostgresDatastoreEnabled.BooleanSetting() {
		s.T().Skip("Skip postgres store tests")
		s.T().SkipNow()
	}

	var err error
	s.legacyDB, err = rocksdb.NewTemp(s.T().Name())
	s.NoError(err)

	s.Require().NoError(err)

	s.ctx = sac.WithAllAccess(context.Background())
	s.postgresDB = pghelper.ForT(s.T(), true)
}

func (s *postgresMigrationSuite) TearDownTest() {
	rocksdbtest.TearDownRocksDB(s.legacyDB)
	s.postgresDB.Teardown(s.T())
}

func (s *postgresMigrationSuite) populateStore(clusterStore store.ClusterStore, clusterID string) (store.FlowStore, []*storage.NetworkFlow) {
	var flows []*storage.NetworkFlow
	for i := 0; i < 30; i++ {
		flow := &storage.NetworkFlow{}
		s.NoError(testutils.FullInit(flow, testutils.UniqueInitializer(), testutils.JSONFieldsFilter))
		flow.LastSeenTimestamp = types.TimestampNow()
		flow.ClusterId = clusterID
		flows = append(flows, flow)
	}
	flowStore := clusterStore.GetFlowStore(clusterID)
	s.NoError(flowStore.UpsertFlows(s.ctx, flows, timestamp.FromProtobuf(flows[len(flows)-1].LastSeenTimestamp)))
	return flowStore, flows
}

func (s *postgresMigrationSuite) verify(flowStore store.FlowStore, flows []*storage.NetworkFlow) {
	fetched, _, err := flowStore.GetAllFlows(s.ctx, &types.Timestamp{})
	s.NoError(err)
	s.Len(fetched, len(flows))
	sort.SliceStable(fetched, func(i, j int) bool {
		return fetched[i].LastSeenTimestamp.Compare(fetched[j].LastSeenTimestamp) < 0
	})
	sort.SliceStable(flows, func(i, j int) bool {
		return flows[i].LastSeenTimestamp.Compare(flows[j].LastSeenTimestamp) < 0
	})
	for i, flow := range flows {
		s.Equal(flow, fetched[i])
	}
}

func (s *postgresMigrationSuite) TestNetworkFlowMigration() {
	newStore := pgStore.NewClusterStore(s.postgresDB.Pool)
	legacyStore := legacy.NewClusterStore(s.legacyDB)

	// Prepare data and write to legacy DB
	_, cluster1Flows := s.populateStore(legacyStore, "cluster1")
	_, cluster2Flows := s.populateStore(legacyStore, "cluster2")

	// Move
	s.NoError(move(s.postgresDB.GetGormDB(), s.postgresDB.Pool, legacyStore))

	// Verify
	s.verify(newStore.GetFlowStore("cluster1"), cluster1Flows)
	s.verify(newStore.GetFlowStore("cluster2"), cluster2Flows)
}
