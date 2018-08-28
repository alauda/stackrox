// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"
import search "github.com/stackrox/rox/pkg/search"
import v1 "github.com/stackrox/rox/generated/api/v1"

// Indexer is an autogenerated mock type for the Indexer type
type Indexer struct {
	mock.Mock
}

// AddAlert provides a mock function with given fields: alert
func (_m *Indexer) AddAlert(alert *v1.Alert) error {
	ret := _m.Called(alert)

	var r0 error
	if rf, ok := ret.Get(0).(func(*v1.Alert) error); ok {
		r0 = rf(alert)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddAlerts provides a mock function with given fields: alerts
func (_m *Indexer) AddAlerts(alerts []*v1.Alert) error {
	ret := _m.Called(alerts)

	var r0 error
	if rf, ok := ret.Get(0).(func([]*v1.Alert) error); ok {
		r0 = rf(alerts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteAlert provides a mock function with given fields: id
func (_m *Indexer) DeleteAlert(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SearchAlerts provides a mock function with given fields: request
func (_m *Indexer) SearchAlerts(request *v1.ParsedSearchRequest) ([]search.Result, error) {
	ret := _m.Called(request)

	var r0 []search.Result
	if rf, ok := ret.Get(0).(func(*v1.ParsedSearchRequest) []search.Result); ok {
		r0 = rf(request)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]search.Result)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*v1.ParsedSearchRequest) error); ok {
		r1 = rf(request)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
