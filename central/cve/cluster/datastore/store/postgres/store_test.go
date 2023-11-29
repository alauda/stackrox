// Code generated by pg-bindings generator. DO NOT EDIT.

//go:build sql_integration

package postgres

import (
	"context"
	"testing"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres/pgtest"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/testutils"
	"github.com/stretchr/testify/suite"
)

type ClusterCvesStoreSuite struct {
	suite.Suite
	store  Store
	testDB *pgtest.TestPostgres
}

func TestClusterCvesStore(t *testing.T) {
	suite.Run(t, new(ClusterCvesStoreSuite))
}

func (s *ClusterCvesStoreSuite) SetupSuite() {

	s.testDB = pgtest.ForT(s.T())
	s.store = New(s.testDB.DB)
}

func (s *ClusterCvesStoreSuite) SetupTest() {
	ctx := sac.WithAllAccess(context.Background())
	tag, err := s.testDB.Exec(ctx, "TRUNCATE cluster_cves CASCADE")
	s.T().Log("cluster_cves", tag)
	s.store = New(s.testDB.DB)
	s.NoError(err)
}

func (s *ClusterCvesStoreSuite) TearDownSuite() {
	s.testDB.Teardown(s.T())
}

func (s *ClusterCvesStoreSuite) TestStore() {
	ctx := sac.WithAllAccess(context.Background())

	store := s.store

	clusterCVE := &storage.ClusterCVE{}
	s.NoError(testutils.FullInit(clusterCVE, testutils.SimpleInitializer(), testutils.JSONFieldsFilter))

	foundClusterCVE, exists, err := store.Get(ctx, clusterCVE.GetId())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundClusterCVE)

	withNoAccessCtx := sac.WithNoAccess(ctx)

	s.NoError(store.Upsert(ctx, clusterCVE))
	foundClusterCVE, exists, err = store.Get(ctx, clusterCVE.GetId())
	s.NoError(err)
	s.True(exists)
	s.Equal(clusterCVE, foundClusterCVE)

	clusterCVECount, err := store.Count(ctx)
	s.NoError(err)
	s.Equal(1, clusterCVECount)
	clusterCVECount, err = store.Count(withNoAccessCtx)
	s.NoError(err)
	s.Zero(clusterCVECount)

	clusterCVEExists, err := store.Exists(ctx, clusterCVE.GetId())
	s.NoError(err)
	s.True(clusterCVEExists)
	s.NoError(store.Upsert(ctx, clusterCVE))
	s.ErrorIs(store.Upsert(withNoAccessCtx, clusterCVE), sac.ErrResourceAccessDenied)

	foundClusterCVE, exists, err = store.Get(ctx, clusterCVE.GetId())
	s.NoError(err)
	s.True(exists)
	s.Equal(clusterCVE, foundClusterCVE)

	s.NoError(store.Delete(ctx, clusterCVE.GetId()))
	foundClusterCVE, exists, err = store.Get(ctx, clusterCVE.GetId())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundClusterCVE)
	s.NoError(store.Delete(withNoAccessCtx, clusterCVE.GetId()))

	var clusterCVEs []*storage.ClusterCVE
	var clusterCVEIDs []string
	for i := 0; i < 200; i++ {
		clusterCVE := &storage.ClusterCVE{}
		s.NoError(testutils.FullInit(clusterCVE, testutils.UniqueInitializer(), testutils.JSONFieldsFilter))
		clusterCVEs = append(clusterCVEs, clusterCVE)
		clusterCVEIDs = append(clusterCVEIDs, clusterCVE.GetId())
	}

	s.NoError(store.UpsertMany(ctx, clusterCVEs))

	clusterCVECount, err = store.Count(ctx)
	s.NoError(err)
	s.Equal(200, clusterCVECount)

	s.NoError(store.DeleteMany(ctx, clusterCVEIDs))

	clusterCVECount, err = store.Count(ctx)
	s.NoError(err)
	s.Equal(0, clusterCVECount)
}
