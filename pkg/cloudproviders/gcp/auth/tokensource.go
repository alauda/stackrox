package auth

import (
	"context"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

// TokenSource provides tokens provided by the credential manager.
type TokenSource struct {
	credManager CredentialsManager
}

// Token returns a managed token.
func (t *TokenSource) Token() (*oauth2.Token, error) {
	creds, err := t.credManager.GetCredentials(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "failed to get credentials")
	}
	return creds.TokenSource.Token()
}
