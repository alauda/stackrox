package deploytime

import (
	deploymentDataStore "github.com/stackrox/rox/central/deployment/datastore"
	"github.com/stackrox/rox/central/detection/deployment"
	"github.com/stackrox/rox/central/detection/utils"
	"github.com/stackrox/rox/central/enrichment"
	"github.com/stackrox/rox/central/sensorevent/service/pipeline"
	"github.com/stackrox/rox/generated/api/v1"
	deploymentMatcher "github.com/stackrox/rox/pkg/compiledpolicies/deployment/matcher"
	"github.com/stackrox/rox/pkg/logging"
)

var logger = logging.LoggerForModule()

type detectorImpl struct {
	policySet deployment.PolicySet

	enricher enrichment.Enricher

	alertManager utils.AlertManager
	deployments  deploymentDataStore.DataStore

	pipeline pipeline.Pipeline
}

// DeploymentUpdated processes a new or updated deployment, generating and updating alerts in the store and returning
// enforcement action.
func (d *detectorImpl) DeploymentUpdated(deployment *v1.Deployment) (string, v1.EnforcementAction, error) {
	// Attempt to enrich the image before detection.
	if _, err := d.enricher.Enrich(deployment); err != nil {
		logger.Errorf("Error enriching deployment %s: %s", deployment.GetName(), err)
	}

	// Asynchronously update risk after processing.
	defer d.enricher.ReprocessDeploymentRiskAsync(deployment)

	// Get alerts for the new deployment from the current set of policies.
	presentAlerts := d.getAlertsForDeployment(deployment)

	// Get the previous alerts for the deployment (if any exist).
	previousAlerts, err := d.alertManager.GetAlertsByDeployment(deployment.GetId())
	if err != nil {
		return "", v1.EnforcementAction_UNSET_ENFORCEMENT, err
	}

	// Perform notifications and update DB.
	if err := d.alertManager.AlertAndNotify(previousAlerts, presentAlerts); err != nil {
		return "", v1.EnforcementAction_UNSET_ENFORCEMENT, err
	}

	// Generate enforcement actions based on the currently generated alerts.
	alertToEnforce, enforcementAction := utils.DetermineEnforcement(presentAlerts)
	return alertToEnforce, enforcementAction, nil
}

// UpsertPolicy adds or updates a policy in the set.
func (d *detectorImpl) UpsertPolicy(policy *v1.Policy) error {
	// Asynchronously update all deployments' risk after processing.
	defer d.enricher.ReprocessRiskAsync()

	// Add policy to set.
	if err := d.policySet.UpsertPolicy(policy); err != nil {
		return err
	}

	// Get the alerts generated by the new policy.
	presentAlerts, err := d.getAlertsForPolicy(policy.GetId())
	if err != nil {
		return err
	}

	// Get any alerts previously existing for the policy (if any exist).
	previousAlerts, err := d.alertManager.GetAlertsByPolicy(policy.GetId())
	if err != nil {
		return err
	}

	// Perform notifications and update DB.
	return d.alertManager.AlertAndNotify(previousAlerts, presentAlerts)
}

// DeploymentRemoved processes a deployment that has been removed, marking all of its alerts as stale.
func (d *detectorImpl) DeploymentRemoved(deployment *v1.Deployment) error {
	oldAlerts, err := d.alertManager.GetAlertsByDeployment(deployment.GetId())
	if err != nil {
		return err
	}
	return d.alertManager.AlertAndNotify(oldAlerts, nil)
}

// RemovePolicy removes a policy from the set.
func (d *detectorImpl) RemovePolicy(policyID string) error {
	if err := d.policySet.RemovePolicy(policyID); err != nil {
		return err
	}

	oldAlerts, err := d.alertManager.GetAlertsByPolicy(policyID)
	if err != nil {
		return err
	}
	return d.alertManager.AlertAndNotify(oldAlerts, nil)
}

func (d *detectorImpl) getAlertsForDeployment(deployment *v1.Deployment) []*v1.Alert {
	// Get the new and old alerts for the deployment.
	// For each cant return an error since our passed function does not return errors.
	var newAlerts []*v1.Alert
	d.policySet.ForEach(func(p *v1.Policy, matcher deploymentMatcher.Matcher) error {
		if violations := matcher(deployment); len(violations) > 0 {
			newAlerts = append(newAlerts, utils.PolicyDeploymentAndViolationsToAlert(p, deployment, violations))
		}
		return nil
	})
	return newAlerts
}

func (d *detectorImpl) getAlertsForPolicy(policyID string) ([]*v1.Alert, error) {
	// Fetch all of the deployments and run them against this new policy
	deployments, err := d.deployments.GetDeployments()
	if err != nil {
		return nil, err
	}

	var newAlerts []*v1.Alert
	for _, deployment := range deployments {
		d.policySet.ForOne(policyID, func(p *v1.Policy, matcher deploymentMatcher.Matcher) error {
			if violations := matcher(deployment); len(violations) > 0 {
				newAlerts = append(newAlerts, utils.PolicyDeploymentAndViolationsToAlert(p, deployment, violations))
			}
			return nil
		})
	}
	return newAlerts, nil
}
