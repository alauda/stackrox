package auth

import (
	"context"
	"time"

	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"cloud.google.com/go/storage"
	"github.com/stackrox/rox/pkg/cloudproviders/gcp/handler"
	"github.com/stackrox/rox/pkg/cloudproviders/gcp/registry"
	"github.com/stackrox/rox/pkg/k8sutil"
	"k8s.io/client-go/kubernetes"
)

const updateTimeout = 1 * time.Hour

type stsClientManagerImpl struct {
	credManager                 CredentialsManager
	storageClientHandler        handler.Handler[*storage.Client]
	securityCenterClientHandler handler.Handler[*securitycenter.Client]
	registryClientHandler       handler.Handler[*registry.Client]
	stopCh                      chan struct{}
}

var _ STSClientManager = &stsClientManagerImpl{}

func fallbackSTSClientManager() STSClientManager {
	mgr := &stsClientManagerImpl{
		credManager:                 &defaultCredentialsManager{},
		storageClientHandler:        handler.NewHandlerNoInit[*storage.Client](),
		securityCenterClientHandler: handler.NewHandlerNoInit[*securitycenter.Client](),
		stopCh:                      make(chan struct{}),
	}
	mgr.updateClients()
	return mgr
}

// NewSTSClientManager creates a new GCP client manager.
func NewSTSClientManager(namespace string, secretName string) STSClientManager {
	restCfg, err := k8sutil.GetK8sInClusterConfig()
	if err != nil {
		log.Error("Could not create GCP credentials manager. Continuing with default credentials chain: ", err)
		return fallbackSTSClientManager()
	}
	k8sClient, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		log.Error("Could not create GCP credentials manager. Continuing with default credentials chain: ", err)
		return fallbackSTSClientManager()
	}
	mgr := &stsClientManagerImpl{
		storageClientHandler:        handler.NewHandlerNoInit[*storage.Client](),
		securityCenterClientHandler: handler.NewHandlerNoInit[*securitycenter.Client](),
		registryClientHandler:       handler.NewHandlerNoInit[*registry.Client](),
		stopCh:                      make(chan struct{}),
	}
	mgr.credManager = newCredentialsManagerImpl(k8sClient, namespace, secretName, mgr.updateClients)
	mgr.updateClients()
	return mgr
}

func (c *stsClientManagerImpl) Start() {
	c.credManager.Start()
	go c.refresh()
}

func (c *stsClientManagerImpl) Stop() {
	close(c.stopCh)
	c.credManager.Stop()
}

func (c *stsClientManagerImpl) refresh() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for {
			select {
			case <-ticker.C:
				c.updateClients()
			case <-c.stopCh:
				ticker.Stop()
				return
			}
		}
	}()
}

func (c *stsClientManagerImpl) updateClients() {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	creds, err := c.credManager.GetCredentials(ctx)
	if err != nil {
		log.Error("Failed to get GCP credentials: ", err)
		return
	}

	if err := c.storageClientHandler.UpdateClient(ctx, creds); err != nil {
		log.Error("Failed to update GCP storage client: ", err)
	}
	if err := c.securityCenterClientHandler.UpdateClient(ctx, creds); err != nil {
		log.Error("Failed to update GCP security center client: ", err)
	}
	if err := c.registryClientHandler.UpdateClient(ctx, creds); err != nil {
		log.Error("Failed to update GCP registry client: ", err)
	}
}

func (c *stsClientManagerImpl) StorageClientHandler() handler.Handler[*storage.Client] {
	return c.storageClientHandler
}

func (c *stsClientManagerImpl) SecurityCenterClientHandler() handler.Handler[*securitycenter.Client] {
	return c.securityCenterClientHandler
}

func (c *stsClientManagerImpl) RegistryClientHandler() handler.Handler[*registry.Client] {
	return c.registryClientHandler
}
