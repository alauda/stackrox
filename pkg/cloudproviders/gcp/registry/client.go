package registry

import (
	"testing"

	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/sync"
	"golang.org/x/oauth2"
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
	ts    oauth2.TokenSource
	mutex sync.RWMutex
}

// NewClient creates a new registry client based on credentials.
func NewClient(ts oauth2.TokenSource) (*Client, error) {
	return &Client{ts: ts}, nil
}

// NewTestClient creates a new test registry client.
func NewTestClient(_ *testing.T) *Client {
	return &Client{}
}

// DockerCredentials returns the Docker credentials held by the client.
func (c *Client) DockerCredentials() *DockerCredentials {
	if c == nil {
		return nil
	}
	token, err := c.ts.Token()
	if err != nil {
		log.Error("Failed to refresh registry token: ", err)
		return &DockerCredentials{}
	}
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return &DockerCredentials{Username: "oauth2accesstoken", Password: token.AccessToken}
}
