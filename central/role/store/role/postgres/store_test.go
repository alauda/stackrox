// Code generated by pg-bindings generator. DO NOT EDIT.

//go:build sql_integration

package postgres

import (
	"context"
	"testing"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/postgres/pgtest"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/testutils"
	"github.com/stackrox/rox/pkg/testutils/envisolator"
	"github.com/stretchr/testify/suite"
)

type RolesStoreSuite struct {
	suite.Suite
	envIsolator *envisolator.EnvIsolator
	store       Store
	testDB      *pgtest.TestPostgres
}

func TestRolesStore(t *testing.T) {
	suite.Run(t, new(RolesStoreSuite))
}

func (s *RolesStoreSuite) SetupSuite() {
	s.envIsolator = envisolator.NewEnvIsolator(s.T())
	s.envIsolator.Setenv(env.PostgresDatastoreEnabled.EnvVar(), "true")

	if !env.PostgresDatastoreEnabled.BooleanSetting() {
		s.T().Skip("Skip postgres store tests")
		s.T().SkipNow()
	}

	s.testDB = pgtest.ForT(s.T())
	s.store = New(s.testDB.Pool)
}

func (s *RolesStoreSuite) SetupTest() {
	ctx := sac.WithAllAccess(context.Background())
	tag, err := s.testDB.Exec(ctx, "TRUNCATE roles CASCADE")
	s.T().Log("roles", tag)
	s.NoError(err)
}

func (s *RolesStoreSuite) TearDownSuite() {
	s.testDB.Teardown(s.T())
	s.envIsolator.RestoreAll()
}

func (s *RolesStoreSuite) TestStore() {
	ctx := sac.WithAllAccess(context.Background())

	store := s.store

	role := &storage.Role{}
	s.NoError(testutils.FullInit(role, testutils.SimpleInitializer(), testutils.JSONFieldsFilter))

	foundRole, exists, err := store.Get(ctx, role.GetName())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundRole)

	withNoAccessCtx := sac.WithNoAccess(ctx)

	s.NoError(store.Upsert(ctx, role))
	foundRole, exists, err = store.Get(ctx, role.GetName())
	s.NoError(err)
	s.True(exists)
	s.Equal(role, foundRole)

	roleCount, err := store.Count(ctx)
	s.NoError(err)
	s.Equal(1, roleCount)
	roleCount, err = store.Count(withNoAccessCtx)
	s.NoError(err)
	s.Zero(roleCount)

	roleExists, err := store.Exists(ctx, role.GetName())
	s.NoError(err)
	s.True(roleExists)
	s.NoError(store.Upsert(ctx, role))
	s.ErrorIs(store.Upsert(withNoAccessCtx, role), sac.ErrResourceAccessDenied)

	foundRole, exists, err = store.Get(ctx, role.GetName())
	s.NoError(err)
	s.True(exists)
	s.Equal(role, foundRole)

	s.NoError(store.Delete(ctx, role.GetName()))
	foundRole, exists, err = store.Get(ctx, role.GetName())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundRole)
	s.ErrorIs(store.Delete(withNoAccessCtx, role.GetName()), sac.ErrResourceAccessDenied)

	var roles []*storage.Role
	for i := 0; i < 200; i++ {
		role := &storage.Role{}
		s.NoError(testutils.FullInit(role, testutils.UniqueInitializer(), testutils.JSONFieldsFilter))
		roles = append(roles, role)
	}

	s.NoError(store.UpsertMany(ctx, roles))

	roleCount, err = store.Count(ctx)
	s.NoError(err)
	s.Equal(200, roleCount)
}
