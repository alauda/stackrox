// Code generated by MockGen. DO NOT EDIT.
// Source: matcher.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	claircore "github.com/quay/claircore"
	gomock "go.uber.org/mock/gomock"
)

// MockMatcher is a mock of Matcher interface.
type MockMatcher struct {
	ctrl     *gomock.Controller
	recorder *MockMatcherMockRecorder
}

// MockMatcherMockRecorder is the mock recorder for MockMatcher.
type MockMatcherMockRecorder struct {
	mock *MockMatcher
}

// NewMockMatcher creates a new mock instance.
func NewMockMatcher(ctrl *gomock.Controller) *MockMatcher {
	mock := &MockMatcher{ctrl: ctrl}
	mock.recorder = &MockMatcherMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMatcher) EXPECT() *MockMatcherMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockMatcher) Close(ctx context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close", ctx)
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockMatcherMockRecorder) Close(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockMatcher)(nil).Close), ctx)
}

// GetVulnerabilities mocks base method.
func (m *MockMatcher) GetVulnerabilities(ctx context.Context, ir *claircore.IndexReport) (*claircore.VulnerabilityReport, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetVulnerabilities", ctx, ir)
	ret0, _ := ret[0].(*claircore.VulnerabilityReport)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetVulnerabilities indicates an expected call of GetVulnerabilities.
func (mr *MockMatcherMockRecorder) GetVulnerabilities(ctx, ir interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetVulnerabilities", reflect.TypeOf((*MockMatcher)(nil).GetVulnerabilities), ctx, ir)
}
