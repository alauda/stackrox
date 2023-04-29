//go:build sql_integration

package store

import (
	"bytes"
	"context"
	"math/rand"
	"testing"

	timestamp "github.com/gogo/protobuf/types"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres/pgtest"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stretchr/testify/suite"
)

type BlobsStoreSuite struct {
	suite.Suite
	store  Store
	testDB *pgtest.TestPostgres
}

func TestBlobsStore(t *testing.T) {
	suite.Run(t, new(BlobsStoreSuite))
}

func (s *BlobsStoreSuite) SetupSuite() {
	s.testDB = pgtest.ForT(s.T())
	s.store = New(s.testDB.DB)
}

func (s *BlobsStoreSuite) SetupTest() {
	ctx := sac.WithAllAccess(context.Background())
	tag, err := s.testDB.Exec(ctx, "TRUNCATE blobs CASCADE")
	s.T().Log("blobs", tag)
	s.NoError(err)
}

func (s *BlobsStoreSuite) TearDownSuite() {
	s.testDB.Teardown(s.T())
}

func (s *BlobsStoreSuite) TestStore() {
	ctx := sac.WithAllAccess(context.Background())

	insertBlob := &storage.Blob{
		Name:         "test",
		LastUpdated:  timestamp.TimestampNow(),
		ModifiedTime: timestamp.TimestampNow(),
	}

	buf := &bytes.Buffer{}
	_, exists, err := s.store.Get(ctx, insertBlob.GetName(), buf)
	s.Require().NoError(err)
	s.Require().False(exists)

	size := 1024*1024 + 16
	randomData := make([]byte, size)
	_, err = rand.Read(randomData)
	s.NoError(err)

	reader := bytes.NewBuffer(randomData)

	s.Require().NoError(s.store.Upsert(ctx, insertBlob, reader))

	buf = &bytes.Buffer{}
	blob, exists, err := s.store.Get(ctx, insertBlob.GetName(), buf)
	s.Require().NoError(err)
	s.Require().True(exists)
	s.NotZero(blob.GetOid())
	s.Equal(insertBlob, blob)
	s.Equal(randomData, buf.Bytes())
}