package auth

import (
	"time"

	"github.com/stackrox/rox/pkg/k8sutil"
	"golang.org/x/oauth2"
	"k8s.io/client-go/kubernetes"
)

const updateTimeout = 1 * time.Hour

type stsClientManagerImpl struct {
	credManager CredentialsManager
	tokenSource *ReuseTokenSourceWithExpiry
}

var _ STSClientManager = &stsClientManagerImpl{}

func fallbackSTSClientManager() STSClientManager {
	credManager := &defaultCredentialsManager{}
	mgr := &stsClientManagerImpl{
		credManager: credManager,
		tokenSource: &ReuseTokenSourceWithExpiry{base: &CredentialManagerTokenSource{credManager}},
	}
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
	mgr := &stsClientManagerImpl{}
	mgr.credManager = newCredentialsManagerImpl(k8sClient, namespace, secretName, mgr.expireToken)
	mgr.tokenSource = &ReuseTokenSourceWithExpiry{base: &CredentialManagerTokenSource{mgr.credManager}}
	return mgr
}

func (c *stsClientManagerImpl) Start() {
	c.credManager.Start()
}

func (c *stsClientManagerImpl) Stop() {
	c.credManager.Stop()
}

func (c *stsClientManagerImpl) TokenSource() oauth2.TokenSource {
	return c.tokenSource
}

func (c *stsClientManagerImpl) expireToken() {
	c.tokenSource.Expire()
}
