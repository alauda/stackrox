// Code generated by pg-bindings generator. DO NOT EDIT.

//go:build sql_integration

package postgres

import (
	"context"
	"testing"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/postgres/pgtest"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/testutils"
	"github.com/stretchr/testify/suite"
)

type ComplianceOperatorClusterScanConfigStatusesStoreSuite struct {
	suite.Suite
	store  Store
	testDB *pgtest.TestPostgres
}

func TestComplianceOperatorClusterScanConfigStatusesStore(t *testing.T) {
	suite.Run(t, new(ComplianceOperatorClusterScanConfigStatusesStoreSuite))
}

func (s *ComplianceOperatorClusterScanConfigStatusesStoreSuite) SetupSuite() {

	s.T().Setenv(features.ComplianceEnhancements.EnvVar(), "true")
	if !features.ComplianceEnhancements.Enabled() {
		s.T().Skip("Skip postgres store tests because feature flag is off")
		s.T().SkipNow()
	}

	s.testDB = pgtest.ForT(s.T())
	s.store = New(s.testDB.DB)
}

func (s *ComplianceOperatorClusterScanConfigStatusesStoreSuite) SetupTest() {
	ctx := sac.WithAllAccess(context.Background())
	tag, err := s.testDB.Exec(ctx, "TRUNCATE compliance_operator_cluster_scan_config_statuses CASCADE")
	s.T().Log("compliance_operator_cluster_scan_config_statuses", tag)
	s.store = New(s.testDB.DB)
	s.NoError(err)
}

func (s *ComplianceOperatorClusterScanConfigStatusesStoreSuite) TearDownSuite() {
	s.testDB.Teardown(s.T())
}

func (s *ComplianceOperatorClusterScanConfigStatusesStoreSuite) TestStore() {
	ctx := sac.WithAllAccess(context.Background())

	store := s.store

	complianceOperatorClusterScanConfigStatus := &storage.ComplianceOperatorClusterScanConfigStatus{}
	s.NoError(testutils.FullInit(complianceOperatorClusterScanConfigStatus, testutils.SimpleInitializer(), testutils.JSONFieldsFilter))

	foundComplianceOperatorClusterScanConfigStatus, exists, err := store.Get(ctx, complianceOperatorClusterScanConfigStatus.GetClusterId())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundComplianceOperatorClusterScanConfigStatus)

	withNoAccessCtx := sac.WithNoAccess(ctx)

	s.NoError(store.Upsert(ctx, complianceOperatorClusterScanConfigStatus))
	foundComplianceOperatorClusterScanConfigStatus, exists, err = store.Get(ctx, complianceOperatorClusterScanConfigStatus.GetClusterId())
	s.NoError(err)
	s.True(exists)
	s.Equal(complianceOperatorClusterScanConfigStatus, foundComplianceOperatorClusterScanConfigStatus)

	complianceOperatorClusterScanConfigStatusCount, err := store.Count(ctx)
	s.NoError(err)
	s.Equal(1, complianceOperatorClusterScanConfigStatusCount)
	complianceOperatorClusterScanConfigStatusCount, err = store.Count(withNoAccessCtx)
	s.NoError(err)
	s.Zero(complianceOperatorClusterScanConfigStatusCount)

	complianceOperatorClusterScanConfigStatusExists, err := store.Exists(ctx, complianceOperatorClusterScanConfigStatus.GetClusterId())
	s.NoError(err)
	s.True(complianceOperatorClusterScanConfigStatusExists)
	s.NoError(store.Upsert(ctx, complianceOperatorClusterScanConfigStatus))
	s.ErrorIs(store.Upsert(withNoAccessCtx, complianceOperatorClusterScanConfigStatus), sac.ErrResourceAccessDenied)

	foundComplianceOperatorClusterScanConfigStatus, exists, err = store.Get(ctx, complianceOperatorClusterScanConfigStatus.GetClusterId())
	s.NoError(err)
	s.True(exists)
	s.Equal(complianceOperatorClusterScanConfigStatus, foundComplianceOperatorClusterScanConfigStatus)

	s.NoError(store.Delete(ctx, complianceOperatorClusterScanConfigStatus.GetClusterId()))
	foundComplianceOperatorClusterScanConfigStatus, exists, err = store.Get(ctx, complianceOperatorClusterScanConfigStatus.GetClusterId())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundComplianceOperatorClusterScanConfigStatus)
	s.ErrorIs(store.Delete(withNoAccessCtx, complianceOperatorClusterScanConfigStatus.GetClusterId()), sac.ErrResourceAccessDenied)

	var complianceOperatorClusterScanConfigStatuss []*storage.ComplianceOperatorClusterScanConfigStatus
	var complianceOperatorClusterScanConfigStatusIDs []string
	for i := 0; i < 200; i++ {
		complianceOperatorClusterScanConfigStatus := &storage.ComplianceOperatorClusterScanConfigStatus{}
		s.NoError(testutils.FullInit(complianceOperatorClusterScanConfigStatus, testutils.UniqueInitializer(), testutils.JSONFieldsFilter))
		complianceOperatorClusterScanConfigStatuss = append(complianceOperatorClusterScanConfigStatuss, complianceOperatorClusterScanConfigStatus)
		complianceOperatorClusterScanConfigStatusIDs = append(complianceOperatorClusterScanConfigStatusIDs, complianceOperatorClusterScanConfigStatus.GetClusterId())
	}

	s.NoError(store.UpsertMany(ctx, complianceOperatorClusterScanConfigStatuss))
	allComplianceOperatorClusterScanConfigStatus, err := store.GetAll(ctx)
	s.NoError(err)
	s.ElementsMatch(complianceOperatorClusterScanConfigStatuss, allComplianceOperatorClusterScanConfigStatus)

	complianceOperatorClusterScanConfigStatusCount, err = store.Count(ctx)
	s.NoError(err)
	s.Equal(200, complianceOperatorClusterScanConfigStatusCount)

	s.NoError(store.DeleteMany(ctx, complianceOperatorClusterScanConfigStatusIDs))

	complianceOperatorClusterScanConfigStatusCount, err = store.Count(ctx)
	s.NoError(err)
	s.Equal(0, complianceOperatorClusterScanConfigStatusCount)
}
