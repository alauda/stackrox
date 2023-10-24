// Code generated by MockGen. DO NOT EDIT.
// Source: manager.go
//
// Generated by this command:
//
//	mockgen -package mocks -destination mocks/manager.go -source manager.go
//
// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	storage "github.com/stackrox/rox/generated/storage"
	gomock "go.uber.org/mock/gomock"
)

// MockManager is a mock of Manager interface.
type MockManager struct {
	ctrl     *gomock.Controller
	recorder *MockManagerMockRecorder
}

// MockManagerMockRecorder is the mock recorder for MockManager.
type MockManagerMockRecorder struct {
	mock *MockManager
}

// NewMockManager creates a new mock instance.
func NewMockManager(ctrl *gomock.Controller) *MockManager {
	mock := &MockManager{ctrl: ctrl}
	mock.recorder = &MockManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockManager) EXPECT() *MockManagerMockRecorder {
	return m.recorder
}

// Backup mocks base method.
func (m *MockManager) Backup(ctx context.Context, id string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Backup", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// Backup indicates an expected call of Backup.
func (mr *MockManagerMockRecorder) Backup(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Backup", reflect.TypeOf((*MockManager)(nil).Backup), ctx, id)
}

// Remove mocks base method.
func (m *MockManager) Remove(ctx context.Context, id string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Remove", ctx, id)
}

// Remove indicates an expected call of Remove.
func (mr *MockManagerMockRecorder) Remove(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Remove", reflect.TypeOf((*MockManager)(nil).Remove), ctx, id)
}

// Test mocks base method.
func (m *MockManager) Test(ctx context.Context, backup *storage.ExternalBackup) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Test", ctx, backup)
	ret0, _ := ret[0].(error)
	return ret0
}

// Test indicates an expected call of Test.
func (mr *MockManagerMockRecorder) Test(ctx, backup any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Test", reflect.TypeOf((*MockManager)(nil).Test), ctx, backup)
}

// Upsert mocks base method.
func (m *MockManager) Upsert(ctx context.Context, backup *storage.ExternalBackup) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Upsert", ctx, backup)
	ret0, _ := ret[0].(error)
	return ret0
}

// Upsert indicates an expected call of Upsert.
func (mr *MockManagerMockRecorder) Upsert(ctx, backup any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Upsert", reflect.TypeOf((*MockManager)(nil).Upsert), ctx, backup)
}
