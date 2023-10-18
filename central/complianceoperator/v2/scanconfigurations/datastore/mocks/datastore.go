// Code generated by MockGen. DO NOT EDIT.
// Source: datastore.go
//
// Generated by this command:
//
//	mockgen -package mocks -destination mocks/datastore.go -source datastore.go
//
// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	v1 "github.com/stackrox/rox/generated/api/v1"
	storage "github.com/stackrox/rox/generated/storage"
	gomock "go.uber.org/mock/gomock"
)

// MockDataStore is a mock of DataStore interface.
type MockDataStore struct {
	ctrl     *gomock.Controller
	recorder *MockDataStoreMockRecorder
}

// MockDataStoreMockRecorder is the mock recorder for MockDataStore.
type MockDataStoreMockRecorder struct {
	mock *MockDataStore
}

// NewMockDataStore creates a new mock instance.
func NewMockDataStore(ctrl *gomock.Controller) *MockDataStore {
	mock := &MockDataStore{ctrl: ctrl}
	mock.recorder = &MockDataStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDataStore) EXPECT() *MockDataStoreMockRecorder {
	return m.recorder
}

// DeleteScanConfiguration mocks base method.
func (m *MockDataStore) DeleteScanConfiguration(ctx context.Context, id string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteScanConfiguration", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteScanConfiguration indicates an expected call of DeleteScanConfiguration.
func (mr *MockDataStoreMockRecorder) DeleteScanConfiguration(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteScanConfiguration", reflect.TypeOf((*MockDataStore)(nil).DeleteScanConfiguration), ctx, id)
}

// GetScanConfigClusterStatus mocks base method.
func (m *MockDataStore) GetScanConfigClusterStatus(ctx context.Context, scanID string) ([]*storage.ComplianceOperatorClusterScanConfigStatus, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetScanConfigClusterStatus", ctx, scanID)
	ret0, _ := ret[0].([]*storage.ComplianceOperatorClusterScanConfigStatus)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetScanConfigClusterStatus indicates an expected call of GetScanConfigClusterStatus.
func (mr *MockDataStoreMockRecorder) GetScanConfigClusterStatus(ctx, scanID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetScanConfigClusterStatus", reflect.TypeOf((*MockDataStore)(nil).GetScanConfigClusterStatus), ctx, scanID)
}

// GetScanConfiguration mocks base method.
func (m *MockDataStore) GetScanConfiguration(ctx context.Context, id string) (*storage.ComplianceOperatorScanConfigurationV2, bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetScanConfiguration", ctx, id)
	ret0, _ := ret[0].(*storage.ComplianceOperatorScanConfigurationV2)
	ret1, _ := ret[1].(bool)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetScanConfiguration indicates an expected call of GetScanConfiguration.
func (mr *MockDataStoreMockRecorder) GetScanConfiguration(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetScanConfiguration", reflect.TypeOf((*MockDataStore)(nil).GetScanConfiguration), ctx, id)
}

// GetScanConfigurations mocks base method.
func (m *MockDataStore) GetScanConfigurations(ctx context.Context, query *v1.Query) ([]*storage.ComplianceOperatorScanConfigurationV2, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetScanConfigurations", ctx, query)
	ret0, _ := ret[0].([]*storage.ComplianceOperatorScanConfigurationV2)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetScanConfigurations indicates an expected call of GetScanConfigurations.
func (mr *MockDataStoreMockRecorder) GetScanConfigurations(ctx, query any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetScanConfigurations", reflect.TypeOf((*MockDataStore)(nil).GetScanConfigurations), ctx, query)
}

// ScanConfigurationExists mocks base method.
func (m *MockDataStore) ScanConfigurationExists(ctx context.Context, scanName string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ScanConfigurationExists", ctx, scanName)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ScanConfigurationExists indicates an expected call of ScanConfigurationExists.
func (mr *MockDataStoreMockRecorder) ScanConfigurationExists(ctx, scanName any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ScanConfigurationExists", reflect.TypeOf((*MockDataStore)(nil).ScanConfigurationExists), ctx, scanName)
}

// UpdateClusterStatus mocks base method.
func (m *MockDataStore) UpdateClusterStatus(ctx context.Context, scanID, clusterID, clusterStatus string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateClusterStatus", ctx, scanID, clusterID, clusterStatus)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateClusterStatus indicates an expected call of UpdateClusterStatus.
func (mr *MockDataStoreMockRecorder) UpdateClusterStatus(ctx, scanID, clusterID, clusterStatus any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateClusterStatus", reflect.TypeOf((*MockDataStore)(nil).UpdateClusterStatus), ctx, scanID, clusterID, clusterStatus)
}

// UpsertScanConfiguration mocks base method.
func (m *MockDataStore) UpsertScanConfiguration(ctx context.Context, scanConfig *storage.ComplianceOperatorScanConfigurationV2) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpsertScanConfiguration", ctx, scanConfig)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpsertScanConfiguration indicates an expected call of UpsertScanConfiguration.
func (mr *MockDataStoreMockRecorder) UpsertScanConfiguration(ctx, scanConfig any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpsertScanConfiguration", reflect.TypeOf((*MockDataStore)(nil).UpsertScanConfiguration), ctx, scanConfig)
}