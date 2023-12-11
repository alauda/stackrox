package utils

import (
	"context"

	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	googleStorage "cloud.google.com/go/storage"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/cloudproviders/gcp/auth"
	"github.com/stackrox/rox/pkg/cloudproviders/gcp/registry"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

// CreateStorageClientFromConfig creates a client based on the GCS integration configuration.
func CreateStorageClientFromConfig(ctx context.Context,
	conf *storage.GCSConfig,
) (*googleStorage.Client, error) {
	if conf.GetUseWorkloadId() {
		return googleStorage.NewClient(ctx)
	}
	return googleStorage.NewClient(ctx, option.WithCredentialsJSON([]byte(conf.GetServiceAccount())))
}

// CreateStorageClientFromConfigWithManager creates a client based on the GCS integration configuration.
func CreateStorageClientFromConfigWithManager(ctx context.Context,
	conf *storage.GCSConfig, manager auth.STSClientManager,
) (*googleStorage.Client, error) {
	if conf.GetUseWorkloadId() {
		return googleStorage.NewClient(ctx, option.WithTokenSource(manager.TokenSource()))
	}
	return googleStorage.NewClient(ctx, option.WithCredentialsJSON([]byte(conf.GetServiceAccount())))
}

// CreateSecurityCenterClientFromConfig creates a client based on the security center config.
func CreateSecurityCenterClientFromConfig(ctx context.Context,
	decCreds []byte, wifEnabled bool,
) (*securitycenter.Client, error) {
	if wifEnabled {
		return securitycenter.NewClient(ctx)
	}
	return securitycenter.NewClient(ctx, option.WithCredentialsJSON([]byte(decCreds)))
}

// CreateSecurityCenterClientFromConfigWithManager creates a client based on the security center config.
func CreateSecurityCenterClientFromConfigWithManager(ctx context.Context,
	manager auth.STSClientManager, decCreds []byte, wifEnabled bool,
) (*securitycenter.Client, error) {
	if wifEnabled {
		return securitycenter.NewClient(ctx, option.WithTokenSource(manager.TokenSource()))
	}
	return securitycenter.NewClient(ctx, option.WithCredentialsJSON([]byte(decCreds)))
}

// CreateRegistryClientFromConfig creates a client based on the image integration config.
func CreateRegistryClientFromConfig(ctx context.Context,
	credsJSON []byte, wifEnabled bool,
) (*registry.Client, error) {
	if wifEnabled {
		creds, err := google.FindDefaultCredentials(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to find default credentials")
		}
		return registry.NewClient(creds.TokenSource)
	}
	creds, err := google.CredentialsFromJSON(ctx, credsJSON)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get credentials from service account JSON")
	}
	return registry.NewClient(creds.TokenSource)
}

// CreateRegistryClientFromConfigWithManager creates a client based on the image integration config.
func CreateRegistryClientFromConfigWithManager(ctx context.Context,
	manager auth.STSClientManager, decCreds []byte, wifEnabled bool,
) (*registry.Client, error) {
	if wifEnabled {
		return registry.NewClient(manager.TokenSource())
	}
	creds, err := google.CredentialsFromJSON(ctx, decCreds)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get credentials from service account JSON")
	}
	return registry.NewClient(creds.TokenSource)
}
