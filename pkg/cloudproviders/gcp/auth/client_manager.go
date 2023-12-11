package auth

import "golang.org/x/oauth2"

// STSClientManager manages GCP clients with short-lived credentials.
type STSClientManager interface {
	Start()
	Stop()
	TokenSource() oauth2.TokenSource
}
