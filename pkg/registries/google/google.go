package google

import (
	"context"
	"net/http"
	"strings"

	"github.com/heroku/docker-registry-client/registry"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/central/cloudproviders/gcp"
	"github.com/stackrox/rox/generated/storage"
	gcpHandler "github.com/stackrox/rox/pkg/cloudproviders/gcp/handler"
	gcpRegistry "github.com/stackrox/rox/pkg/cloudproviders/gcp/registry"
	"github.com/stackrox/rox/pkg/cloudproviders/gcp/utils"
	"github.com/stackrox/rox/pkg/errorhelpers"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/registries/docker"
	"github.com/stackrox/rox/pkg/registries/types"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/rox/pkg/sync"
)

var log = logging.LoggerForModule()

var _ types.Registry = (*googleRegistry)(nil)

type googleRegistry struct {
	*docker.Registry

	config          *storage.GoogleConfig
	integration     *storage.ImageIntegration
	clientHandler   gcpHandler.Handler[*gcpRegistry.Client]
	mutex           sync.RWMutex
	project         string
	disableRepoList bool
}

func validateConfiguration(config *storage.GoogleConfig) error {
	errorList := errorhelpers.NewErrorList("Google Validation")
	if config.GetEndpoint() == "" {
		errorList.AddString("Endpoint must be specified for Google registry (e.g. gcr.io, us.gcr.io, eu.gcr.io)")
	}
	if config.GetServiceAccount() == "" {
		errorList.AddString("Service account must be specified for Google registry")
	}
	return errorList.ToError()
}

// Match overrides the underlying Match function in docker.Registry because our google registries are scoped by
// GCP projects
func (g *googleRegistry) Match(image *storage.ImageName) bool {
	if stringutils.GetUpTo(image.GetRemote(), "/") != g.project {
		return false
	}
	client, done := g.clientHandler.GetClient()
	defer done()
	if err := g.updateDockerRegistry(client.DockerCredentials()); err != nil {
		log.Error("Failed to update registry: ", err)
	}
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.Registry.Match(image)
}

// Metadata returns the metadata via this registry's implementation.
func (g *googleRegistry) Metadata(image *storage.Image) (*storage.ImageMetadata, error) {
	client, done := g.clientHandler.GetClient()
	defer done()
	if err := g.updateDockerRegistry(client.DockerCredentials()); err != nil {
		return nil, errors.Wrap(err, "failed to update registry")
	}
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.Registry.Metadata(image)
}

// Config returns the config via this registry's implementation.
func (g *googleRegistry) Config() *types.Config {
	client, done := g.clientHandler.GetClient()
	defer done()
	if err := g.updateDockerRegistry(client.DockerCredentials()); err != nil {
		log.Error("Failed to update registry: ", err)
	}
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.Registry.Config()
}

// HTTPClient returns the *http.Client used to contact the registry.
// TODO: fix race condition
func (g *googleRegistry) HTTPClient() *http.Client {
	client, done := g.clientHandler.GetClient()
	defer done()
	if err := g.updateDockerRegistry(client.DockerCredentials()); err != nil {
		log.Error("Failed to update registry: ", err)
	}
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.Registry.HTTPClient()
}

// Test tests the current registry and makes sure that it is working properly
func (g *googleRegistry) Test() error {
	client, done := g.clientHandler.GetClient()
	defer done()
	if err := g.updateDockerRegistry(client.DockerCredentials()); err != nil {
		return errors.Wrap(err, "failed to update registry")
	}

	g.mutex.RLock()
	defer g.mutex.RUnlock()
	_, err := g.Registry.Client.Repositories()
	// the following code taken from generic Test method
	if err != nil {
		log.Errorf("error testing google integration: %v", err)
		if e, _ := err.(*registry.ClientError); e != nil {
			return errors.Errorf("error testing google integration (code: %d). Please check Central logs for full error", e.Code())
		}
		return err
	}
	return nil
}

// Creator provides the type and registries.Creator to add to the registries Registry.
func Creator() (string, func(integration *storage.ImageIntegration) (types.Registry, error)) {
	return "google", func(integration *storage.ImageIntegration) (types.Registry, error) {
		return NewRegistry(integration, false)
	}
}

// CreatorWithoutRepoList provides the type and registries.Creator to add to the registries Registry.
// Populating the internal repo list will be disabled.
func CreatorWithoutRepoList() (string, func(integration *storage.ImageIntegration) (types.Registry, error)) {
	return "google", func(integration *storage.ImageIntegration) (types.Registry, error) {
		return NewRegistry(integration, true)
	}
}

// NewRegistry creates an image integration based on the Google config. It also checks against
// the specified Google project as a part of the registry match.
func NewRegistry(integration *storage.ImageIntegration, disableRepoList bool) (*googleRegistry, error) {
	config := integration.GetGoogle()
	if config == nil {
		return nil, errors.New("Google configuration required")
	}
	if err := validateConfiguration(config); err != nil {
		return nil, err
	}

	var (
		handler gcpHandler.Handler[*gcpRegistry.Client]
		err     error
	)
	if features.CloudCredentials.Enabled() {
		handler, err = utils.CreateRegistryHandlerFromConfigWithManager(
			context.Background(),
			gcp.Singleton(),
			[]byte(config.GetServiceAccount()),
			config.GetWifEnabled(),
		)
	} else {
		handler, err = utils.CreateRegistryHandlerFromConfig(
			context.Background(),
			[]byte(config.GetServiceAccount()),
			config.GetWifEnabled(),
		)
	}
	if err != nil {
		return nil, errors.Wrap(err, "could not create Google registry client handler")
	}
	reg := &googleRegistry{
		config:          config,
		integration:     integration,
		clientHandler:   handler,
		project:         strings.ToLower(config.GetProject()),
		disableRepoList: disableRepoList,
	}
	client, done := reg.clientHandler.GetClient()
	defer done()
	if err := reg.updateDockerRegistry(client.DockerCredentials()); err != nil {
		return nil, errors.Wrap(err, "failed to update registry")
	}
	return reg, nil
}

func (g *googleRegistry) updateDockerRegistry(creds *gcpRegistry.DockerCredentials) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if g.Registry != nil && g.Registry.Config().Password == creds.GetPassword() {
		return nil
	}
	conf := docker.Config{
		Endpoint:        g.config.GetEndpoint(),
		Username:        creds.GetUsername(),
		Password:        creds.GetPassword(),
		DisableRepoList: g.disableRepoList,
	}
	reg, err := docker.NewDockerRegistryWithConfig(conf, g.integration)
	if err != nil {
		return errors.Wrap(err, "failed to create Docker registry")
	}
	g.Registry = reg
	return nil
}
