package tests

import (
	"context"
	"testing"

	v2 "github.com/stackrox/rox/generated/api/v2"
	"github.com/stackrox/rox/pkg/testutils/centralgrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type ComplianceE2ETestSuite struct {
	suite.Suite

	ctx           context.Context
	service       v2.ComplianceProfileServiceClient
	collectionIDs []string
}

func (s *ComplianceE2ETestSuite) SetupSuite() {

	s.ctx = context.Background()
	conn := centralgrpc.GRPCConnectionToCentral(s.T())
	s.service = v2.NewComplianceProfileServiceClient(conn)

}

func (s *ComplianceE2ETestSuite) TestCreateRunScanConfiguration(t *testing.T) {
	assert.True(t, true)
}

func (s *ComplianceE2ETestSuite) TestGetProfiles(t *testing.T) {
	profileID := "ocp-cis-4.2"
	id := &v2.ResourceByID{
		Id: profileID,
	}
	profile, err := s.service.GetComplianceProfile(s.ctx, id)
	assert.NoError(t, err)
	assert.Equal(t, profile.GetId(), profileID)
}

func (s *ComplianceE2ETestSuite) TestGetComplianceIntegrations(t *testing.T) {
	assert.True(t, true)
}
