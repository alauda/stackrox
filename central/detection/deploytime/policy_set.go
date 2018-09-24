package deploytime

import (
	policyDatastore "github.com/stackrox/rox/central/policy/datastore"
	"github.com/stackrox/rox/generated/api/v1"
	deploymentMatcher "github.com/stackrox/rox/pkg/compiledpolicies/deployment/matcher"
)

// PolicySet is a set of build time policies.
//go:generate mockery -name=PolicySet
type PolicySet interface {
	ForOne(string, func(*v1.Policy, deploymentMatcher.Matcher) error) error
	ForEach(fe func(*v1.Policy, deploymentMatcher.Matcher) error, runtime bool) error

	UpsertPolicy(*v1.Policy) error
	RemovePolicy(policyID string) error
	RemoveNotifier(notifierID string) error
}

// NewPolicySet returns a new instance of a PolicySet.
func NewPolicySet(store policyDatastore.DataStore) PolicySet {
	return &setImpl{
		policyIDToPolicy:         make(map[string]*v1.Policy),
		policyIDToMatcher:        make(map[string]deploymentMatcher.Matcher),
		runtimePolicyIDToMatcher: make(map[string]deploymentMatcher.Matcher),
		policyStore:              store,
	}
}
