package mtls

import "time"

type issueOptions struct {
	namespace     string
	signerProfile string
	notAfter      time.Time
	notBefore     time.Time
}

func (o *issueOptions) apply(opts []IssueCertOption) {
	for _, opt := range opts {
		opt(o)
	}
}

// IssueCertOption is an additional option for certificate issuance.
type IssueCertOption func(o *issueOptions)

// WithNamespace requests certificates to be issued for the given namespace.
func WithNamespace(namespace string) IssueCertOption {
	return func(o *issueOptions) {
		o.namespace = namespace
	}
}

// WithValidityExpiringInHours requests certificates with validity expiring in the order of hours.
// This option is suitable for issuing init bundles which cannot be revoked.
func WithValidityExpiringInHours() IssueCertOption {
	return func(o *issueOptions) {
		o.signerProfile = ephemeralProfileWithExpirationInHours
	}
}

// WithValidityExpiringInDays requests certificates with validity expiring in the order of days.
func WithValidityExpiringInDays() IssueCertOption {
	return func(o *issueOptions) {
		o.signerProfile = ephemeralProfileWithExpirationInDays
	}
}

func WithNotAfter(notAfter time.Time) IssueCertOption {
	return func(o *issueOptions) {
		o.notAfter = notAfter
	}
}

func WithNotBefore(notBefore time.Time) IssueCertOption {
	return func(o *issueOptions) {
		o.notBefore = notBefore
	}
}
