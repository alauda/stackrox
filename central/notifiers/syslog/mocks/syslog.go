// Code generated by MockGen. DO NOT EDIT.
// Source: syslog.go

// Package mocks is a generated GoMock package.
package mocks

import (
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// MocksyslogSender is a mock of syslogSender interface
type MocksyslogSender struct {
	ctrl     *gomock.Controller
	recorder *MocksyslogSenderMockRecorder
}

// MocksyslogSenderMockRecorder is the mock recorder for MocksyslogSender
type MocksyslogSenderMockRecorder struct {
	mock *MocksyslogSender
}

// NewMocksyslogSender creates a new mock instance
func NewMocksyslogSender(ctrl *gomock.Controller) *MocksyslogSender {
	mock := &MocksyslogSender{ctrl: ctrl}
	mock.recorder = &MocksyslogSenderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MocksyslogSender) EXPECT() *MocksyslogSenderMockRecorder {
	return m.recorder
}

// SendSyslog mocks base method
func (m *MocksyslogSender) SendSyslog(syslogBytes []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendSyslog", syslogBytes)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendSyslog indicates an expected call of SendSyslog
func (mr *MocksyslogSenderMockRecorder) SendSyslog(syslogBytes interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendSyslog", reflect.TypeOf((*MocksyslogSender)(nil).SendSyslog), syslogBytes)
}

// Cleanup mocks base method
func (m *MocksyslogSender) Cleanup() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Cleanup")
}

// Cleanup indicates an expected call of Cleanup
func (mr *MocksyslogSenderMockRecorder) Cleanup() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Cleanup", reflect.TypeOf((*MocksyslogSender)(nil).Cleanup))
}
