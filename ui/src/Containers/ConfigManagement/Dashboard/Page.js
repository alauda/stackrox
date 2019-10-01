import React from 'react';
import contextLabels from 'messages/context';
import { standardTypes } from 'constants/entityTypes';

import DashboardLayout from 'Components/DashboardLayout';
import Header from './Header/Header';

import PolicyViolationsBySeverity from './widgets/PolicyViolationsBySeverity';
import ComplianceByControls from './widgets/ComplianceByControls';
import UsersWithMostClusterAdminRoles from './widgets/UsersWithMostClusterAdminRoles';
import SecretsMostUsedAcrossDeployments from './widgets/SecretsMostUsedAcrossDeployments';

const ConfigManagementDashboardPage = () => {
    return (
        <DashboardLayout headerText={contextLabels.CONFIG_MANAGEMENT} headerComponents={<Header />}>
            <PolicyViolationsBySeverity />
            <ComplianceByControls
                className="pdf-page"
                isConfigMangement="true"
                standardOptions={[
                    standardTypes.CIS_Docker_v1_2_0,
                    standardTypes.CIS_Kubernetes_v1_4_1
                ]}
            />
            <UsersWithMostClusterAdminRoles />
            <SecretsMostUsedAcrossDeployments />
        </DashboardLayout>
    );
};
export default ConfigManagementDashboardPage;
