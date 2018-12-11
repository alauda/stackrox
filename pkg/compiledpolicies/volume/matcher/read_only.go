package matcher

import (
	"fmt"

	"github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
)

func init() {
	compilers = append(compilers, newReadOnlyMatcher)
}

func newReadOnlyMatcher(policy *v1.Policy) (Matcher, error) {
	volumePolicy := policy.GetFields().GetVolumePolicy()
	if volumePolicy.GetSetReadOnly() == nil {
		return nil, nil
	}

	readOnly := volumePolicy.GetReadOnly()
	matcher := &readOnlyMatcherImpl{&readOnly}
	return matcher.match, nil
}

type readOnlyMatcherImpl struct {
	readOnly *bool
}

func (p *readOnlyMatcherImpl) match(volume *storage.Volume) []*v1.Alert_Violation {
	var violations []*v1.Alert_Violation
	if *p.readOnly != volume.GetReadOnly() {
		v := &v1.Alert_Violation{
			Message: fmt.Sprintf("Readony matched configs policy: %t", *p.readOnly),
		}
		violations = append(violations, v)
	}
	return violations
}
