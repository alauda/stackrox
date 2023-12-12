package auth

import (
	"time"

	"github.com/stackrox/rox/pkg/auth/tokensource"
	"github.com/stackrox/rox/pkg/k8sutil"
	"golang.org/x/oauth2"
	"k8s.io/client-go/kubernetes"
)

const updateTimeout = 1 * time.Hour

type stsTokenManagerImpl struct {
	credManager CredentialsManager
	tokenSource *tokensource.ReuseTokenSourceWithExpiry
}

var _ STSTokenManager = &stsTokenManagerImpl{}

func fallbackSTSClientManager() STSTokenManager {
	credManager := &defaultCredentialsManager{}
	mgr := &stsTokenManagerImpl{
		credManager: credManager,
		tokenSource: tokensource.NewReuseTokenSourceWithExpiry(&CredentialManagerTokenSource{credManager}),
	}
	return mgr
}

// NewSTSTokenManager creates a new GCP token manager.
func NewSTSTokenManager(namespace string, secretName string) STSTokenManager {
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
	mgr := &stsTokenManagerImpl{}
	mgr.credManager = newCredentialsManagerImpl(k8sClient, namespace, secretName, mgr.expireToken)
	mgr.tokenSource = tokensource.NewReuseTokenSourceWithExpiry(&CredentialManagerTokenSource{mgr.credManager})
	return mgr
}

func (c *stsTokenManagerImpl) Start() {
	c.credManager.Start()
}

func (c *stsTokenManagerImpl) Stop() {
	c.credManager.Stop()
}

func (c *stsTokenManagerImpl) TokenSource() oauth2.TokenSource {
	return c.tokenSource
}

func (c *stsTokenManagerImpl) expireToken() {
	c.tokenSource.Expire()
}
