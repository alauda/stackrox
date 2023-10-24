// Code generated by MockGen. DO NOT EDIT.
// Source: pgxpool_conn.go
//
// Generated by this command:
//
//	mockgen -package mocks -destination mocks/pgxpool_conn.go -source pgxpool_conn.go
//
// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	pgconn "github.com/jackc/pgconn"
	pgx "github.com/jackc/pgx/v4"
	gomock "go.uber.org/mock/gomock"
)

// MockPgxPoolConn is a mock of PgxPoolConn interface.
type MockPgxPoolConn struct {
	ctrl     *gomock.Controller
	recorder *MockPgxPoolConnMockRecorder
}

// MockPgxPoolConnMockRecorder is the mock recorder for MockPgxPoolConn.
type MockPgxPoolConnMockRecorder struct {
	mock *MockPgxPoolConn
}

// NewMockPgxPoolConn creates a new mock instance.
func NewMockPgxPoolConn(ctrl *gomock.Controller) *MockPgxPoolConn {
	mock := &MockPgxPoolConn{ctrl: ctrl}
	mock.recorder = &MockPgxPoolConnMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPgxPoolConn) EXPECT() *MockPgxPoolConnMockRecorder {
	return m.recorder
}

// Begin mocks base method.
func (m *MockPgxPoolConn) Begin(ctx context.Context) (pgx.Tx, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Begin", ctx)
	ret0, _ := ret[0].(pgx.Tx)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Begin indicates an expected call of Begin.
func (mr *MockPgxPoolConnMockRecorder) Begin(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Begin", reflect.TypeOf((*MockPgxPoolConn)(nil).Begin), ctx)
}

// CopyFrom mocks base method.
func (m *MockPgxPoolConn) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CopyFrom", ctx, tableName, columnNames, rowSrc)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CopyFrom indicates an expected call of CopyFrom.
func (mr *MockPgxPoolConnMockRecorder) CopyFrom(ctx, tableName, columnNames, rowSrc any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CopyFrom", reflect.TypeOf((*MockPgxPoolConn)(nil).CopyFrom), ctx, tableName, columnNames, rowSrc)
}

// Exec mocks base method.
func (m *MockPgxPoolConn) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, sql}
	for _, a := range arguments {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Exec", varargs...)
	ret0, _ := ret[0].(pgconn.CommandTag)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Exec indicates an expected call of Exec.
func (mr *MockPgxPoolConnMockRecorder) Exec(ctx, sql any, arguments ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, sql}, arguments...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Exec", reflect.TypeOf((*MockPgxPoolConn)(nil).Exec), varargs...)
}

// Query mocks base method.
func (m *MockPgxPoolConn) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, sql}
	for _, a := range args {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Query", varargs...)
	ret0, _ := ret[0].(pgx.Rows)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Query indicates an expected call of Query.
func (mr *MockPgxPoolConnMockRecorder) Query(ctx, sql any, args ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, sql}, args...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Query", reflect.TypeOf((*MockPgxPoolConn)(nil).Query), varargs...)
}

// QueryRow mocks base method.
func (m *MockPgxPoolConn) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	m.ctrl.T.Helper()
	varargs := []any{ctx, sql}
	for _, a := range args {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "QueryRow", varargs...)
	ret0, _ := ret[0].(pgx.Row)
	return ret0
}

// QueryRow indicates an expected call of QueryRow.
func (mr *MockPgxPoolConnMockRecorder) QueryRow(ctx, sql any, args ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, sql}, args...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueryRow", reflect.TypeOf((*MockPgxPoolConn)(nil).QueryRow), varargs...)
}

// Release mocks base method.
func (m *MockPgxPoolConn) Release() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Release")
}

// Release indicates an expected call of Release.
func (mr *MockPgxPoolConnMockRecorder) Release() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Release", reflect.TypeOf((*MockPgxPoolConn)(nil).Release))
}

// SendBatch mocks base method.
func (m *MockPgxPoolConn) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendBatch", ctx, b)
	ret0, _ := ret[0].(pgx.BatchResults)
	return ret0
}

// SendBatch indicates an expected call of SendBatch.
func (mr *MockPgxPoolConnMockRecorder) SendBatch(ctx, b any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendBatch", reflect.TypeOf((*MockPgxPoolConn)(nil).SendBatch), ctx, b)
}
