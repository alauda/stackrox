package checksi38

import (
	"github.com/stackrox/rox/central/compliance/checks/common"
	"github.com/stackrox/rox/central/compliance/framework"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/features"
)

const (
	controlID = "NIST_SP_800_53:SI_3_(8)"

	interpretationText = `TODO`
)

func init() {
	framework.MustRegisterNewCheckIfFlagEnabled(
		framework.CheckMetadata{
			ID:                 controlID,
			Scope:              framework.ClusterKind,
			DataDependencies:   []string{"Policies"},
			InterpretationText: interpretationText,
		},
		func(ctx framework.ComplianceContext) {
			framework.Pass(ctx, "StackRox is installed") // TODO(viswa): Get text
			common.CheckAnyPolicyInLifeCycle(ctx, storage.LifecycleStage_RUNTIME)
		}, features.NistSP800_53)
}
