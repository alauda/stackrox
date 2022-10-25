// Code generated by MockGen. DO NOT EDIT.
// Source: datastore.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	types "github.com/stackrox/rox/pkg/transitional/protocompat/types"
	gomock "github.com/golang/mock/gomock"
	v1 "github.com/stackrox/rox/generated/api/v1"
	storage "github.com/stackrox/rox/generated/storage"
	search "github.com/stackrox/rox/pkg/search"
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

// Count mocks base method.
func (m *MockDataStore) Count(ctx context.Context, q *v1.Query) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Count", ctx, q)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Count indicates an expected call of Count.
func (mr *MockDataStoreMockRecorder) Count(ctx, q interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Count", reflect.TypeOf((*MockDataStore)(nil).Count), ctx, q)
}

// EnrichImageWithSuppressedCVEs mocks base method.
func (m *MockDataStore) EnrichImageWithSuppressedCVEs(image *storage.Image) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "EnrichImageWithSuppressedCVEs", image)
}

// EnrichImageWithSuppressedCVEs indicates an expected call of EnrichImageWithSuppressedCVEs.
func (mr *MockDataStoreMockRecorder) EnrichImageWithSuppressedCVEs(image interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EnrichImageWithSuppressedCVEs", reflect.TypeOf((*MockDataStore)(nil).EnrichImageWithSuppressedCVEs), image)
}

// Exists mocks base method.
func (m *MockDataStore) Exists(ctx context.Context, id string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Exists", ctx, id)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Exists indicates an expected call of Exists.
func (mr *MockDataStoreMockRecorder) Exists(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Exists", reflect.TypeOf((*MockDataStore)(nil).Exists), ctx, id)
}

// Get mocks base method.
func (m *MockDataStore) Get(ctx context.Context, id string) (*storage.ImageCVE, bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", ctx, id)
	ret0, _ := ret[0].(*storage.ImageCVE)
	ret1, _ := ret[1].(bool)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Get indicates an expected call of Get.
func (mr *MockDataStoreMockRecorder) Get(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockDataStore)(nil).Get), ctx, id)
}

// GetBatch mocks base method.
func (m *MockDataStore) GetBatch(ctx context.Context, id []string) ([]*storage.ImageCVE, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBatch", ctx, id)
	ret0, _ := ret[0].([]*storage.ImageCVE)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBatch indicates an expected call of GetBatch.
func (mr *MockDataStoreMockRecorder) GetBatch(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBatch", reflect.TypeOf((*MockDataStore)(nil).GetBatch), ctx, id)
}

// Search mocks base method.
func (m *MockDataStore) Search(ctx context.Context, q *v1.Query) ([]search.Result, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Search", ctx, q)
	ret0, _ := ret[0].([]search.Result)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Search indicates an expected call of Search.
func (mr *MockDataStoreMockRecorder) Search(ctx, q interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Search", reflect.TypeOf((*MockDataStore)(nil).Search), ctx, q)
}

// SearchImageCVEs mocks base method.
func (m *MockDataStore) SearchImageCVEs(ctx context.Context, q *v1.Query) ([]*v1.SearchResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SearchImageCVEs", ctx, q)
	ret0, _ := ret[0].([]*v1.SearchResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SearchImageCVEs indicates an expected call of SearchImageCVEs.
func (mr *MockDataStoreMockRecorder) SearchImageCVEs(ctx, q interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SearchImageCVEs", reflect.TypeOf((*MockDataStore)(nil).SearchImageCVEs), ctx, q)
}

// SearchRawImageCVEs mocks base method.
func (m *MockDataStore) SearchRawImageCVEs(ctx context.Context, q *v1.Query) ([]*storage.ImageCVE, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SearchRawImageCVEs", ctx, q)
	ret0, _ := ret[0].([]*storage.ImageCVE)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SearchRawImageCVEs indicates an expected call of SearchRawImageCVEs.
func (mr *MockDataStoreMockRecorder) SearchRawImageCVEs(ctx, q interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SearchRawImageCVEs", reflect.TypeOf((*MockDataStore)(nil).SearchRawImageCVEs), ctx, q)
}

// Suppress mocks base method.
func (m *MockDataStore) Suppress(ctx context.Context, start *types.Timestamp, duration *types.Duration, cves ...string) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, start, duration}
	for _, a := range cves {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Suppress", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Suppress indicates an expected call of Suppress.
func (mr *MockDataStoreMockRecorder) Suppress(ctx, start, duration interface{}, cves ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, start, duration}, cves...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Suppress", reflect.TypeOf((*MockDataStore)(nil).Suppress), varargs...)
}

// Unsuppress mocks base method.
func (m *MockDataStore) Unsuppress(ctx context.Context, cves ...string) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx}
	for _, a := range cves {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Unsuppress", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Unsuppress indicates an expected call of Unsuppress.
func (mr *MockDataStoreMockRecorder) Unsuppress(ctx interface{}, cves ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx}, cves...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Unsuppress", reflect.TypeOf((*MockDataStore)(nil).Unsuppress), varargs...)
}
