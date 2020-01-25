// Code generated by MockGen. DO NOT EDIT.
// Source: policy_set.go

// Package mocks is a generated GoMock package.
package mocks

import (
	gomock "github.com/golang/mock/gomock"
	storage "github.com/stackrox/rox/generated/storage"
	detection "github.com/stackrox/rox/pkg/detection"
	reflect "reflect"
)

// MockPolicySet is a mock of PolicySet interface
type MockPolicySet struct {
	ctrl     *gomock.Controller
	recorder *MockPolicySetMockRecorder
}

// MockPolicySetMockRecorder is the mock recorder for MockPolicySet
type MockPolicySetMockRecorder struct {
	mock *MockPolicySet
}

// NewMockPolicySet creates a new mock instance
func NewMockPolicySet(ctrl *gomock.Controller) *MockPolicySet {
	mock := &MockPolicySet{ctrl: ctrl}
	mock.recorder = &MockPolicySetMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockPolicySet) EXPECT() *MockPolicySetMockRecorder {
	return m.recorder
}

// Compiler mocks base method
func (m *MockPolicySet) Compiler() detection.PolicyCompiler {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Compiler")
	ret0, _ := ret[0].(detection.PolicyCompiler)
	return ret0
}

// Compiler indicates an expected call of Compiler
func (mr *MockPolicySetMockRecorder) Compiler() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Compiler", reflect.TypeOf((*MockPolicySet)(nil).Compiler))
}

// ForOne mocks base method
func (m *MockPolicySet) ForOne(policyID string, pt detection.PolicyExecutor) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ForOne", policyID, pt)
	ret0, _ := ret[0].(error)
	return ret0
}

// ForOne indicates an expected call of ForOne
func (mr *MockPolicySetMockRecorder) ForOne(policyID, pt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ForOne", reflect.TypeOf((*MockPolicySet)(nil).ForOne), policyID, pt)
}

// ForEach mocks base method
func (m *MockPolicySet) ForEach(pt detection.PolicyExecutor) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ForEach", pt)
	ret0, _ := ret[0].(error)
	return ret0
}

// ForEach indicates an expected call of ForEach
func (mr *MockPolicySetMockRecorder) ForEach(pt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ForEach", reflect.TypeOf((*MockPolicySet)(nil).ForEach), pt)
}

// GetCompiledPolicies mocks base method
func (m *MockPolicySet) GetCompiledPolicies() map[string]detection.CompiledPolicy {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCompiledPolicies")
	ret0, _ := ret[0].(map[string]detection.CompiledPolicy)
	return ret0
}

// GetCompiledPolicies indicates an expected call of GetCompiledPolicies
func (mr *MockPolicySetMockRecorder) GetCompiledPolicies() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCompiledPolicies", reflect.TypeOf((*MockPolicySet)(nil).GetCompiledPolicies))
}

// Recompile mocks base method
func (m *MockPolicySet) Recompile(policyID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Recompile", policyID)
	ret0, _ := ret[0].(error)
	return ret0
}

// Recompile indicates an expected call of Recompile
func (mr *MockPolicySetMockRecorder) Recompile(policyID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Recompile", reflect.TypeOf((*MockPolicySet)(nil).Recompile), policyID)
}

// UpsertPolicy mocks base method
func (m *MockPolicySet) UpsertPolicy(arg0 *storage.Policy) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpsertPolicy", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpsertPolicy indicates an expected call of UpsertPolicy
func (mr *MockPolicySetMockRecorder) UpsertPolicy(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpsertPolicy", reflect.TypeOf((*MockPolicySet)(nil).UpsertPolicy), arg0)
}

// RemovePolicy mocks base method
func (m *MockPolicySet) RemovePolicy(policyID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemovePolicy", policyID)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemovePolicy indicates an expected call of RemovePolicy
func (mr *MockPolicySetMockRecorder) RemovePolicy(policyID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemovePolicy", reflect.TypeOf((*MockPolicySet)(nil).RemovePolicy), policyID)
}
