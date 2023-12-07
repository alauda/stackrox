package registry

import (
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/sync"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var log = logging.LoggerForModule()

// DockerCredentials holds credentials required to log in to a Docker registry.
type DockerCredentials struct {
	Username string
	Password string
}

// GetUsername returns the user name.
func (d *DockerCredentials) GetUsername() string {
	if d == nil {
		return ""
	}
	return d.Username
}

// GetPassword returns the password.
func (d *DockerCredentials) GetPassword() string {
	if d == nil {
		return ""
	}
	return d.Password
}

// Client holds and refreshes credentials for Google container registries.
type Client struct {
	creds *google.Credentials
	token *oauth2.Token
	mutex sync.RWMutex
}

// NewClient creates a new registry client based on credentials.
func NewClient(creds *google.Credentials) (*Client, error) {
	token, err := creds.TokenSource.Token()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get token")
	}
	log.Infof("created token: access_token=%q, refresh_token=%q, expiry=%q", token.AccessToken, token.RefreshToken, token.Expiry)
	return &Client{creds: creds, token: token}, nil
}

// NewTestClient creates a new test registry client.
func NewTestClient(t *testing.T) *Client {
	return &Client{token: &oauth2.Token{Expiry: time.Now().Add(240 * time.Hour)}}
}

func (c *Client) refreshToken() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.token.Expiry.After(time.Now()) {
		return nil
	}
	token, err := c.creds.TokenSource.Token()
	if err != nil {
		return errors.Wrap(err, "failed to get token")
	}
	c.token = token
	log.Infof("refreshed token: access_token=%q, refresh_token=%q, expiry=%q", token.AccessToken, token.RefreshToken, token.Expiry)
	return nil
}

// DockerCredentials returns the Docker credentials held by the client.
// Credentials are refreshed as needed.
func (c *Client) DockerCredentials() *DockerCredentials {
	if c == nil {
		return nil
	}
	if err := c.refreshToken(); err != nil {
		log.Error("Failed to refresh registry token: ", err)
	}
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return &DockerCredentials{Username: "oauth2accesstoken", Password: c.token.AccessToken}
}
