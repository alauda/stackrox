package auth

import (
	"context"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/sync"
	"golang.org/x/oauth2"
)

// CredentialManagerTokenSource provides tokens provided by the credential manager.
type CredentialManagerTokenSource struct {
	credManager CredentialsManager
}

// Token returns a managed token.
func (t *CredentialManagerTokenSource) Token() (*oauth2.Token, error) {
	creds, err := t.credManager.GetCredentials(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "failed to get credentials")
	}
	return creds.TokenSource.Token()
}

// ReuseTokenSourceWithExpiry works like oauth2.ReuseTokenSource but with
// and additional manual expiry method that forces a token refresh.
type ReuseTokenSourceWithExpiry struct {
	token     *oauth2.Token
	base      oauth2.TokenSource
	mutex     sync.Mutex
	isExpired bool
}

// Token returns a valid token.
func (t *ReuseTokenSourceWithExpiry) Token() (*oauth2.Token, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	if !t.isExpired && t.token.Valid() {
		return t.token, nil
	}
	token, err := t.base.Token()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get token")
	}
	t.token = token
	t.isExpired = false
	return t.token, nil
}

func (t *ReuseTokenSourceWithExpiry) Expire() {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.isExpired = true
}
