package manager_test

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	clusterDatastoreMocks "github.com/stackrox/rox/central/cluster/datastore/mocks"
	complianceDataMocks "github.com/stackrox/rox/central/compliance/data/mocks"
	"github.com/stackrox/rox/central/compliance/manager"
	complianceMgrMocks "github.com/stackrox/rox/central/compliance/manager/mocks"
	"github.com/stackrox/rox/central/compliance/standards"
	complianceStoreMocks "github.com/stackrox/rox/central/compliance/store/mocks"
	deploymentDatastoreMocks "github.com/stackrox/rox/central/deployment/datastore/mocks"
	nodeStoreMocks "github.com/stackrox/rox/central/node/store/mocks"
	scrapeMocks "github.com/stackrox/rox/central/scrape/mocks"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stretchr/testify/suite"
)

type managerTestSuite struct {
	suite.Suite

	manager manager.ComplianceManager

	mockCtrl              *gomock.Controller
	mockStandardImplStore *complianceMgrMocks.MockStandardImplementationStore
	mockScheduleStore     *complianceMgrMocks.MockScheduleStore
	mockClusterStore      *clusterDatastoreMocks.MockDataStore
	mockNodeStore         *nodeStoreMocks.MockGlobalStore
	mockDeploymentStore   *deploymentDatastoreMocks.MockDataStore
	mockDataRepoFactory   *complianceDataMocks.MockRepositoryFactory
	mockScrapeFactory     *scrapeMocks.MockFactory
	mockResultsStore      *complianceStoreMocks.MockStore
}

func TestManager(t *testing.T) {
	suite.Run(t, new(managerTestSuite))
}

func (s *managerTestSuite) TestExpandSelection_OneOne() {
	pairs, err := s.manager.ExpandSelection("cluster1", "standard1")
	s.NoError(err)
	s.ElementsMatch(pairs, []manager.ClusterStandardPair{
		{ClusterID: "cluster1", StandardID: "standard1"},
	})
}

func (s *managerTestSuite) TestExpandSelection_AllOne_OK() {
	s.mockClusterStore.EXPECT().GetClusters().Return([]*storage.Cluster{
		{
			Id: "cluster1",
		},
		{
			Id: "cluster2",
		},
	}, nil)
	pairs, err := s.manager.ExpandSelection(manager.Wildcard, "standard1")
	s.NoError(err)
	s.ElementsMatch(pairs, []manager.ClusterStandardPair{
		{ClusterID: "cluster1", StandardID: "standard1"},
		{ClusterID: "cluster2", StandardID: "standard1"},
	})
}

func (s *managerTestSuite) TestExpandSelection_AllOne_GetClustersError() {
	s.mockClusterStore.EXPECT().GetClusters().Return(nil, errors.New("some error"))
	_, err := s.manager.ExpandSelection(manager.Wildcard, "standard1")
	s.Error(err)
}

func (s *managerTestSuite) TestExpandSelection_OneAll_OK() {
	s.mockStandardImplStore.EXPECT().ListStandardImplementations().Return([]manager.StandardImplementation{
		{Standard: &standards.Standard{ID: "standard1"}},
		{Standard: &standards.Standard{ID: "standard2"}},
	})
	pairs, err := s.manager.ExpandSelection("cluster1", manager.Wildcard)
	s.NoError(err)
	s.ElementsMatch(pairs, []manager.ClusterStandardPair{
		{ClusterID: "cluster1", StandardID: "standard1"},
		{ClusterID: "cluster1", StandardID: "standard2"},
	})
}

func (s *managerTestSuite) TestExpandSelection_AllAll_OK() {
	s.mockClusterStore.EXPECT().GetClusters().Return([]*storage.Cluster{
		{Id: "cluster1"},
		{Id: "cluster2"},
	}, nil)
	s.mockStandardImplStore.EXPECT().ListStandardImplementations().Return([]manager.StandardImplementation{
		{Standard: &standards.Standard{ID: "standard1"}},
		{Standard: &standards.Standard{ID: "standard2"}},
	})
	pairs, err := s.manager.ExpandSelection(manager.Wildcard, manager.Wildcard)
	s.NoError(err)
	s.ElementsMatch(pairs, []manager.ClusterStandardPair{
		{ClusterID: "cluster1", StandardID: "standard1"},
		{ClusterID: "cluster1", StandardID: "standard2"},
		{ClusterID: "cluster2", StandardID: "standard1"},
		{ClusterID: "cluster2", StandardID: "standard2"},
	})
}

func (s *managerTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockStandardImplStore = complianceMgrMocks.NewMockStandardImplementationStore(s.mockCtrl)
	s.mockScheduleStore = complianceMgrMocks.NewMockScheduleStore(s.mockCtrl)
	s.mockClusterStore = clusterDatastoreMocks.NewMockDataStore(s.mockCtrl)
	s.mockNodeStore = nodeStoreMocks.NewMockGlobalStore(s.mockCtrl)
	s.mockDeploymentStore = deploymentDatastoreMocks.NewMockDataStore(s.mockCtrl)
	s.mockScrapeFactory = scrapeMocks.NewMockFactory(s.mockCtrl)
	s.mockResultsStore = complianceStoreMocks.NewMockStore(s.mockCtrl)

	s.mockScheduleStore.EXPECT().ListSchedules().Return(nil, nil)
	var err error
	s.manager, err = manager.NewManager(s.mockStandardImplStore, s.mockScheduleStore, s.mockClusterStore, s.mockNodeStore, s.mockDeploymentStore, s.mockDataRepoFactory, s.mockScrapeFactory, s.mockResultsStore)
	s.Require().NoError(err)
}

func (s *managerTestSuite) TearDownTest() {
	s.mockCtrl.Finish()
}
