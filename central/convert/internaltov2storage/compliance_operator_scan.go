package internaltov2storage

import (
	"github.com/stackrox/rox/generated/internalapi/central"
	"github.com/stackrox/rox/generated/storage"
)

const (
	ocpComplianceLabelsKey = "compliance.openshift.io/"
)

var (
	suiteKey = ocpComplianceLabelsKey + "suite"

	scanTypeToV2 = map[string]storage.ScanType{
		"Node":     storage.ScanType_NODE_SCAN,
		"Platform": storage.ScanType_PLATFORM_SCAN,
	}
)

// ComplianceOperatorScanObject converts internal api V2 compliance scan object to a V2 storage compliance scan object
func ComplianceOperatorScanObject(sensorData *central.ComplianceOperatorScanV2, clusterID string) *storage.ComplianceOperatorScanV2 {
	return &storage.ComplianceOperatorScanV2{
		Id:             sensorData.GetId(),
		ScanConfigName: sensorData.GetLabels()[suiteKey],
		ScanName:       sensorData.GetName(),
		ClusterId:      clusterID,
		ClusterName:    "", // TODO, probably do this in the datastore
		Errors:         sensorData.GetStatus().ErrorMessage,
		Profile: &storage.ProfileShim{
			ProfileId: sensorData.GetProfileId(),
		},
		Labels:      sensorData.GetLabels(),
		Annotations: sensorData.GetAnnotations(),
		ScanType:    scanTypeToV2[sensorData.GetScanType()],
		Status: &storage.ScanStatus{
			Phase:    sensorData.GetStatus().GetPhase(),
			Result:   sensorData.GetStatus().GetResult(),
			Warnings: sensorData.GetStatus().GetWarnings(),
		},
		CreatedTime:      sensorData.GetStatus().GetStartTime(),
		LastExecutedTime: sensorData.GetStatus().GetEndTime(),
	}
}
