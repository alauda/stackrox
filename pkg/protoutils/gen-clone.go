// Code generated by genny. DO NOT EDIT.
// This file was automatically generated by genny.
// Any changes will be lost if this file is regenerated.
// see https://github.com/mauricelam/genny

package protoutils

import "github.com/stackrox/rox/generated/api/v1"
import "github.com/stackrox/rox/generated/storage"

// *v1.Policy represents a generic proto type that we clone.

// CloneV1Policy is a (generic) wrapper around proto.Clone that is strongly typed.
func CloneV1Policy(val *v1.Policy) *v1.Policy {
	return protoCloneWrapper(val).(*v1.Policy)
}

// *storage.Deployment represents a generic proto type that we clone.

// CloneStorageDeployment is a (generic) wrapper around proto.Clone that is strongly typed.
func CloneStorageDeployment(val *storage.Deployment) *storage.Deployment {
	return protoCloneWrapper(val).(*storage.Deployment)
}

// *v1.Alert represents a generic proto type that we clone.

// CloneV1Alert is a (generic) wrapper around proto.Clone that is strongly typed.
func CloneV1Alert(val *v1.Alert) *v1.Alert {
	return protoCloneWrapper(val).(*v1.Alert)
}
