package billingmetrics

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	bmstore "github.com/stackrox/rox/central/billingmetrics/store"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/pkg/auth/permissions"
	"github.com/stackrox/rox/pkg/grpc/authz"
	"github.com/stackrox/rox/pkg/grpc/authz/perrpc"
	"github.com/stackrox/rox/pkg/grpc/authz/user"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/sac/resources"
	"google.golang.org/grpc"
)

var (
	log        = logging.LoggerForModule()
	authorizer = perrpc.FromMap(map[authz.Authorizer][]string{
		user.With(permissions.View(resources.Administration)): {
			"/v1.BillingMetricsService/GetMetrics",
			"/v1.BillingMetricsService/GetMax",
		}})
)

type serviceImpl struct {
	v1.UnimplementedBillingMetricsServiceServer

	store bmstore.Store
}

// New returns a new Service instance using the given DataStore.
func New(datastore bmstore.Store) Service {
	return &serviceImpl{
		store: datastore,
	}
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterBillingMetricsServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterBillingMetricsServiceHandler(ctx, mux, conn)
}

// AuthFuncOverride specifies the auth criteria for this API.
func (s *serviceImpl) AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error) {
	return ctx, authorizer.Authorized(ctx, fullMethodName)
}

func (s *serviceImpl) GetMetrics(ctx context.Context, req *v1.BillingMetricsRequest) (*v1.BillingMetricsResponse, error) {
	metrics, err := s.store.Get(ctx, req.GetFrom(), req.GetTo())
	if err != nil {
		return nil, fmt.Errorf("cannot get billing metrics: %w", err)
	}
	rec := make([]*v1.BillingMetricsResponse_BillingMetricsRecord, 0, len(metrics))
	for _, m := range metrics {
		rec = append(rec, &v1.BillingMetricsResponse_BillingMetricsRecord{Ts: m.Ts, Metrics: (*v1.SecuredResourcesMetrics)(m.Sr)})
	}
	return &v1.BillingMetricsResponse{Record: rec}, nil
}

func (s *serviceImpl) GetMax(ctx context.Context, req *v1.BillingMetricsRequest) (*v1.BillingMetricsMaxResponse, error) {
	metrics, err := s.store.Get(ctx, req.GetFrom(), req.GetTo())
	if err != nil {
		return nil, fmt.Errorf("cannot get billing metrics: %w", err)
	}
	max := &v1.BillingMetricsMaxResponse{}
	for _, m := range metrics {
		if n := m.GetSr().GetNodes(); n >= max.Nodes {
			max.Nodes = n
			max.NodesTs = m.GetTs()
		}
		if ms := m.GetSr().GetCores(); ms >= max.Cores {
			max.Cores = ms
			max.CoresTs = m.GetTs()
		}
	}
	return max, nil
}
