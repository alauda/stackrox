package auth

import "golang.org/x/oauth2"

// STSTokenManager manages GCP clients with short-lived credentials.
type STSTokenManager interface {
	Start()
	Stop()
	TokenSource() oauth2.TokenSource
}
