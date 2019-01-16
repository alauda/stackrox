package mappings

import (
	"github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/pkg/search"
)

// OptionsMap is exposed for e2e test.
var OptionsMap = search.OptionsMapFromMap(map[search.FieldLabel]*v1.SearchField{
	search.Violation:      search.NewStringField(v1.SearchCategory_ALERTS, "alert.violations.message"),
	search.ViolationState: search.NewViolationStateField(v1.SearchCategory_ALERTS, "alert.state"),

	search.LifecycleStage: search.NewLifecycleField(v1.SearchCategory_ALERTS, "alert.lifecycle_stage"),
	search.Enforcement:    search.NewEnforcementField(v1.SearchCategory_ALERTS, "alert.enforcement.action"),

	search.PolicyID:   search.NewField(v1.SearchCategory_ALERTS, "alert.policy.id", v1.SearchDataType_SEARCH_STRING, search.OptionHidden),
	search.PolicyName: search.NewStringField(v1.SearchCategory_ALERTS, "alert.policy.name"),
	search.Category:   search.NewStringField(v1.SearchCategory_ALERTS, "alert.policy.categories"),
	search.Severity:   search.NewSeverityField(v1.SearchCategory_ALERTS, "alert.policy.severity"),

	search.DeploymentID:   search.NewField(v1.SearchCategory_ALERTS, "alert.deployment.id", v1.SearchDataType_SEARCH_STRING, search.OptionHidden),
	search.Cluster:        search.NewStringField(v1.SearchCategory_ALERTS, "alert.deployment.cluster_name"),
	search.Namespace:      search.NewStringField(v1.SearchCategory_ALERTS, "alert.deployment.namespace"),
	search.Label:          search.NewMapField(v1.SearchCategory_ALERTS, "alert.deployment.labels"),
	search.DeploymentName: search.NewStringField(v1.SearchCategory_ALERTS, "alert.deployment.name"),
})
