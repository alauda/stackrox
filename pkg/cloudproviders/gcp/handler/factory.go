package handler

import (
	"context"

	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"cloud.google.com/go/storage"
	"github.com/stackrox/rox/pkg/cloudproviders/gcp/registry"
	"github.com/stackrox/rox/pkg/cloudproviders/gcp/types"
	"github.com/stackrox/rox/pkg/errox"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
)

// ClientFactory creates a GCP storage client.
//
//go:generate mockgen-wrapper
type ClientFactory[T types.GcpSDKClients] interface {
	NewClient(ctx context.Context, creds *google.Credentials) (T, error)
}

// GetClientFactory retrieves the ClientFactory for the given type.
func GetClientFactory[T types.GcpSDKClients](client T) (ClientFactory[T], error) {
	switch any(client).(type) {
	case *storage.Client:
		return &storageClientFactory[T]{}, nil
	case *securitycenter.Client:
		return &securityCenterClientFactory[T]{}, nil
	case *registry.Client:
		return &registryClientFactory[T]{}, nil
	}
	return nil, errox.InvariantViolation.Newf("client factory not found for type: %T", *new(T))
}

type storageClientFactory[T types.GcpSDKClients] struct{}

func (s *storageClientFactory[T]) NewClient(ctx context.Context, creds *google.Credentials) (T, error) {
	client, err := storage.NewClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return *new(T), err
	}
	return any(client).(T), nil
}

type securityCenterClientFactory[T types.GcpSDKClients] struct{}

func (s *securityCenterClientFactory[T]) NewClient(ctx context.Context, creds *google.Credentials) (T, error) {
	client, err := securitycenter.NewClient(ctx, option.WithCredentials(creds),
		option.WithGRPCDialOption(grpc.WithContextDialer(proxy.AwareDialContext)))
	if err != nil {
		return *new(T), err
	}
	return any(client).(T), nil
}

type registryClientFactory[T types.GcpSDKClients] struct{}

func (s *registryClientFactory[T]) NewClient(_ context.Context, creds *google.Credentials) (T, error) {
	client, err := registry.NewClient(creds)
	if err != nil {
		return *new(T), err
	}
	return any(client).(T), nil
}
