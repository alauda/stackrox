import React, { useContext } from 'react';
import pluralize from 'pluralize';

import CollapsibleSection from 'Components/CollapsibleSection';
import DateTimeField from 'Components/DateTimeField';
import Metadata from 'Components/Metadata';
import RiskScore from 'Components/RiskScore';
import StatusChip from 'Components/StatusChip';
import Tabs from 'Components/Tabs';
import TabContent from 'Components/TabContent';
import workflowStateContext from 'Containers/workflowStateContext';
import { getPolicyTableColumns } from 'Containers/VulnMgmt/List/Policies/VulnMgmtListPolicies';
import { getCveTableColumns } from 'Containers/VulnMgmt/List/Cves/VulnMgmtListCves';
import entityTypes from 'constants/entityTypes';
import { overviewLimit } from 'constants/workflowPages.constants';
import { entityGridContainerClassName } from 'Containers/Workflow/WorkflowEntityPage';
import { exportCvesAsCsv } from 'services/VulnerabilitiesService';
import { getCveExportName } from 'utils/vulnerabilityUtils';

import FixableCveExportButton from '../../VulnMgmtComponents/FixableCveExportButton';
import TopRiskyEntitiesByVulnerabilities from '../../widgets/TopRiskyEntitiesByVulnerabilities';
import RecentlyDetectedVulnerabilities from '../../widgets/RecentlyDetectedVulnerabilities';
import TopRiskiestImagesAndComponents from '../../widgets/TopRiskiestImagesAndComponents';
import DeploymentsWithMostSeverePolicyViolations from '../../widgets/DeploymentsWithMostSeverePolicyViolations';
import RelatedEntitiesSideList from '../RelatedEntitiesSideList';
import TableWidget from '../TableWidget';

const emptyCluster = {
    componentCount: 0,
    deploymentCount: 0,
    id: '',
    imageCount: 0,
    name: '',
    policyCount: 0,
    policyStatus: {
        status: '',
        failingPolicies: []
    },
    priority: 0,
    status: {
        orchestratorMetadata: {
            buildDate: '',
            version: 'N/A'
        }
    },
    vulnCount: 0,
    vulnerabilities: []
};

const VulnMgmtClusterOverview = ({ data, entityContext }) => {
    const workflowState = useContext(workflowStateContext);

    // guard against incomplete GraphQL-cached data
    const safeData = { ...emptyCluster, ...data };

    const { priority, policyStatus, status, istioEnabled, vulnerabilities, id } = safeData;

    if (!status || !policyStatus) return null;

    const { orchestratorMetadata = null } = status;
    const { buildDate = '', version = 'N/A' } = orchestratorMetadata;
    const { failingPolicies } = policyStatus;
    const fixableCves = vulnerabilities.filter(cve => cve.isFixable);

    function customCsvExportHandler() {
        const { useCase } = workflowState;
        const pageEntityType = workflowState.getCurrentEntityType();
        const entityName = safeData.name;
        const csvName = getCveExportName(useCase, pageEntityType, entityName);

        const stateWithFixable = workflowState.setSearch({ 'Fixed By': 'r/.*' });

        exportCvesAsCsv(csvName, stateWithFixable);
    }

    function yesNoMaybe(value) {
        if (!value && value !== false) {
            return '—';
        }
        return value ? 'Yes' : 'No';
    }

    const metadataKeyValuePairs = [
        {
            key: 'Build Date',
            value: <DateTimeField date={buildDate} asString />
        },
        {
            key: 'K8s version',
            value: version
        },
        {
            key: 'Istio Enabled',
            value: yesNoMaybe(istioEnabled)
        }
    ];

    const clusterStats = [
        <RiskScore key="risk-score" score={priority} />,
        <React.Fragment key="policy-status">
            <span className="pb-2">Policy status:</span>
            <StatusChip status={policyStatus.status} />
        </React.Fragment>
    ];

    const newEntityContext = { ...entityContext, [entityTypes.CLUSTER]: id };
    const cveActions = (
        <FixableCveExportButton
            disabled={!fixableCves || !fixableCves.length}
            clickHandler={customCsvExportHandler}
        />
    );

    return (
        <div className="flex h-full">
            <div className="flex flex-col flex-grow min-w-0">
                <CollapsibleSection title="Cluster Details">
                    <div className={entityGridContainerClassName}>
                        <div className="s-1">
                            <Metadata
                                className="h-full min-w-48 bg-base-100 pdf-page"
                                keyValuePairs={metadataKeyValuePairs}
                                statTiles={clusterStats}
                                title="Details & Metadata"
                            />
                        </div>
                        <div className="sx-1 lg:sx-2 sy-1 h-55">
                            <TopRiskyEntitiesByVulnerabilities
                                defaultSelection={entityTypes.NAMESPACE}
                                limit={overviewLimit}
                                riskEntityTypes={[
                                    entityTypes.NAMESPACE,
                                    entityTypes.DEPLOYMENT,
                                    entityTypes.IMAGE
                                ]}
                                entityContext={newEntityContext}
                                small
                            />
                        </div>
                        <div className="s-1">
                            <RecentlyDetectedVulnerabilities
                                limit={overviewLimit}
                                entityContext={newEntityContext}
                            />
                        </div>
                        <div className="s-1">
                            <TopRiskiestImagesAndComponents
                                limit={overviewLimit}
                                entityContext={newEntityContext}
                            />
                        </div>
                        <div className="s-1">
                            <DeploymentsWithMostSeverePolicyViolations
                                limit={overviewLimit}
                                entityContext={newEntityContext}
                            />
                        </div>
                    </div>
                </CollapsibleSection>

                <CollapsibleSection title="Cluster Findings">
                    <div className="pdf-page pdf-stretch pdf-new flex shadow rounded relative rounded bg-base-100 mb-4 ml-4 mr-4">
                        <Tabs
                            hasTabSpacing
                            headers={[{ text: 'Policies' }, { text: 'Fixable CVEs' }]}
                        >
                            <TabContent>
                                <TableWidget
                                    header={`${failingPolicies.length} failing ${pluralize(
                                        entityTypes.POLICY,
                                        failingPolicies.length
                                    )} across this cluster`}
                                    rows={failingPolicies}
                                    entityType={entityTypes.POLICY}
                                    noDataText="No failing policies"
                                    className="bg-base-100"
                                    columns={getPolicyTableColumns(workflowState)}
                                    idAttribute="id"
                                />
                            </TabContent>
                            <TabContent>
                                <TableWidget
                                    header={`${fixableCves.length} fixable ${pluralize(
                                        entityTypes.CVE,
                                        fixableCves.length
                                    )} found across this cluster`}
                                    headerActions={cveActions}
                                    rows={fixableCves}
                                    entityType={entityTypes.CVE}
                                    noDataText="No fixable CVEs available in this cluster"
                                    className="bg-base-100"
                                    columns={getCveTableColumns(workflowState)}
                                    idAttribute="cve"
                                />
                            </TabContent>
                        </Tabs>
                    </div>
                </CollapsibleSection>
            </div>
            <RelatedEntitiesSideList
                entityType={entityTypes.CLUSTER}
                entityContext={newEntityContext}
                data={safeData}
            />
        </div>
    );
};

export default VulnMgmtClusterOverview;
