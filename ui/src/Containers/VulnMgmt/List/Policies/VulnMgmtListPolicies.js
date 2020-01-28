/* eslint-disable react/jsx-no-bind */
import React, { useState } from 'react';
import PropTypes from 'prop-types';
import gql from 'graphql-tag';
import pluralize from 'pluralize';
import { Power, Bell, BellOff, Trash2 } from 'react-feather';
import { connect } from 'react-redux';

import {
    defaultHeaderClassName,
    nonSortableHeaderClassName,
    defaultColumnClassName
} from 'Components/Table';
import DateTimeField from 'Components/DateTimeField';
import Dialog from 'Components/Dialog';
import IconWithState from 'Components/IconWithState';
import PanelButton from 'Components/PanelButton';
import RowActionButton from 'Components/RowActionButton';
import StatusChip from 'Components/StatusChip';
import SeverityLabel from 'Components/SeverityLabel';
import TableCountLink from 'Components/workflow/TableCountLink';
import WorkflowListPage from 'Containers/Workflow/WorkflowListPage';
import entityTypes from 'constants/entityTypes';
import { LIST_PAGE_SIZE } from 'constants/workflowPages.constants';
import queryService from 'modules/queryService';
import { workflowListPropTypes, workflowListDefaultProps } from 'constants/entityPageProps';
import { actions as notificationActions } from 'reducers/notifications';
import { deletePolicies } from 'services/PoliciesService';
import removeEntityContextColumns from 'utils/tableUtils';
import { policySortFields } from 'constants/sortFields';

import { UNSCOPED_POLICY_LIST_FRAGMENT } from 'Containers/VulnMgmt/VulnMgmt.fragments';

export const defaultPolicySort = [
    // @TODO: remove this fake default sort on Policy name, when latest violation is available
    {
        id: policySortFields.POLICY,
        desc: false
    }
    // {
    //     id: policySortFields.LATEST_VIOLATION,
    //     desc: true
    // },
    // {
    //     id: policySortFields.POLICY_STATUS,
    //     desc: false
    // }
];

export function getPolicyTableColumns(workflowState) {
    // to determine whether to show the counts as links in the table when not in pure POLICY state
    const inFindingsSection = workflowState.getCurrentEntity().entityType !== entityTypes.POLICY;
    const tableColumns = [
        {
            Header: 'id',
            headerClassName: 'hidden',
            className: 'hidden',
            accessor: 'id'
        },
        {
            Header: 'statuses',
            headerClassName: 'w-16 invisible',
            className: `w-16 ${defaultColumnClassName}`,
            Cell: ({ original }) => {
                const { disabled, notifiers } = original;
                const policyEnabled = !disabled;
                const hasNotifiers = !!(notifiers && notifiers.length);

                return (
                    <div className="flex">
                        <IconWithState Icon={Power} enabled={policyEnabled} />
                        <IconWithState
                            Icon={hasNotifiers ? Bell : BellOff}
                            enabled={hasNotifiers}
                        />
                    </div>
                );
            }
        },
        {
            Header: `Policy`,
            headerClassName: `w-1/8 ${defaultHeaderClassName}`,
            className: `w-1/8 ${defaultColumnClassName}`,
            accessor: 'name',
            sortField: policySortFields.POLICY
        },
        {
            Header: `Description`,
            headerClassName: `w-1/6 ${nonSortableHeaderClassName}`,
            className: `w-1/6 ${defaultColumnClassName}`,
            accessor: 'description',
            id: 'description',
            sortable: false
        },
        {
            Header: `Policy Status`,
            headerClassName: `w-1/10 text-center ${defaultHeaderClassName}`,
            className: `w-1/10 ${defaultColumnClassName}`,
            Cell: ({ original, pdf }) => (
                <div className="flex justify-center w-full">
                    <StatusChip status={original.policyStatus} asString={pdf} />
                </div>
            ),
            id: 'policyStatus',
            accessor: 'policyStatus',
            sortField: policySortFields.POLICY_STATUS
        },
        {
            Header: `Last Updated`,
            headerClassName: `w-1/10 ${defaultHeaderClassName}`,
            className: `w-1/10 ${defaultColumnClassName}`,
            Cell: ({ original, pdf }) => {
                const { lastUpdated } = original;
                return <DateTimeField date={lastUpdated} asString={pdf} />;
            },
            accessor: 'lastUpdated',
            sortField: policySortFields.LAST_UPDATED
        },
        {
            Header: `Latest Violation`,
            headerClassName: `w-1/10 ${defaultHeaderClassName}`,
            className: `w-1/10 ${defaultColumnClassName}`,
            Cell: ({ original, pdf }) => {
                const { latestViolation } = original;
                return <DateTimeField date={latestViolation} asString={pdf} />;
            },
            accessor: 'latestViolation',
            sortField: policySortFields.LATEST_VIOLATION
        },
        {
            Header: `Severity`,
            headerClassName: `w-1/10 text-left ${defaultHeaderClassName}`,
            className: `w-1/10 ${defaultColumnClassName}`,
            Cell: ({ original }) => <SeverityLabel severity={original.severity} />,
            accessor: 'severity',
            id: 'severity',
            sortField: policySortFields.SEVERITY
        },
        {
            Header: `Deployments`,
            entityType: entityTypes.DEPLOYMENT,
            headerClassName: `w-1/8 ${defaultHeaderClassName}`,
            className: `w-1/8 ${defaultColumnClassName}`,
            Cell: ({ original, pdf }) => (
                <TableCountLink
                    entityType={entityTypes.DEPLOYMENT}
                    count={original.deploymentCount}
                    textOnly={inFindingsSection || pdf}
                    selectedRowId={original.id}
                />
            ),
            accessor: 'deploymentCount',
            id: 'deploymentCount',
            sortField: policySortFields.DEPLOYMENTS,
            sortable: false // not performant as of 2020-01-28
        },
        {
            Header: `Lifecyle`,
            headerClassName: `w-1/10 ${defaultHeaderClassName}`,
            className: `w-1/10 ${defaultColumnClassName}`,
            Cell: ({ original }) => {
                const { lifecycleStages } = original;
                if (!lifecycleStages || !lifecycleStages.length) return 'No lifecycle stages';
                const lowercasedLifecycles = lifecycleStages
                    .map(stage => stage.toLowerCase())
                    .join(', ');

                return <span>{lowercasedLifecycles}</span>;
            },
            accessor: 'lifecycleStages',
            id: 'lifecycleStages',
            sortField: policySortFields.LIFECYCLE_STAGE
        },
        {
            Header: `Enforcement`,
            headerClassName: `w-1/10 ${defaultHeaderClassName}`,
            className: `w-1/10 ${defaultColumnClassName}`,
            Cell: ({ original }) => {
                const { enforcementActions } = original;
                return enforcementActions && enforcementActions.length ? 'Yes' : 'No';
            },
            accessor: 'enforcementActions',
            id: 'enforcementActions',
            sortField: policySortFields.ENFORCEMENT
        }
    ];

    return removeEntityContextColumns(tableColumns, workflowState);
}

const VulnMgmtPolicies = ({
    selectedRowId,
    search,
    sort,
    page,
    data,
    totalResults,
    addToast,
    removeToast,
    refreshTrigger,
    setRefreshTrigger
}) => {
    const [selectedPolicyIds, setSelectedPolicyIds] = useState([]);
    const [bulkActionPolicyIds, setBulkActionPolicyIds] = useState([]);

    const POLICIES_QUERY = gql`
        query getPolicies($policyQuery: String, $pagination: Pagination) {
            results: policies(query: $policyQuery, pagination: $pagination) {
                ...unscopedPolicyFields
                deploymentCount
            }
            count: policyCount(query: $policyQuery)
        }
        ${UNSCOPED_POLICY_LIST_FRAGMENT}
    `;

    const tableSort = sort || defaultPolicySort;
    const queryOptions = {
        variables: {
            policyQuery: queryService.objectToWhereClause({
                ...search,
                Category: 'Vulnerability Management',
                cachebuster: refreshTrigger
            }),
            pagination: queryService.getPagination(tableSort, page, LIST_PAGE_SIZE)
        }
    };

    const deletePolicy = policyId => e => {
        e.stopPropagation();

        const policiesToDelete = policyId ? [policyId] : selectedPolicyIds;

        if (policiesToDelete.length) {
            setBulkActionPolicyIds(policiesToDelete);
        } else {
            throw new Error('Logic error: tried to delete with no Policy IDs selected.');
        }
    };

    function hideDialog() {
        setBulkActionPolicyIds([]);
    }

    function makeDeleteRequest() {
        deletePolicies(bulkActionPolicyIds)
            .then(() => {
                setSelectedPolicyIds([]);

                // changing this param value on the query vars, to force the query to refetch
                setRefreshTrigger(Math.random());

                addToast(
                    `Successfully deleted ${bulkActionPolicyIds.length} ${pluralize(
                        'policy',
                        bulkActionPolicyIds.length
                    )}`
                );
                setTimeout(removeToast, 2000);

                hideDialog();
            })
            .catch(evt => {
                addToast(`Could not suppress all of the selected policies: ${evt.message}`);
                setTimeout(removeToast, 3000);
            });
    }

    const renderRowActionButtons = ({ id }) => (
        <div className="flex border-2 border-r-2 border-base-400 bg-base-100">
            <RowActionButton
                text="Delete this Policy"
                onClick={deletePolicy(id)}
                icon={
                    <Trash2 className="hover:bg-alert-200 text-alert-600 hover:text-alert-700 mt-1 h-4 w-4" />
                }
            />
        </div>
    );

    const tableHeaderComponents = (
        <React.Fragment>
            <PanelButton
                icon={<Trash2 className="h-4 w-4" />}
                className="btn-icon btn-alert"
                onClick={deletePolicy()}
                disabled={selectedPolicyIds.length === 0}
                tooltip="Delete Selected Policies"
            >
                Delete
            </PanelButton>
        </React.Fragment>
    );

    return (
        <>
            <WorkflowListPage
                data={data}
                totalResults={totalResults}
                query={POLICIES_QUERY}
                queryOptions={queryOptions}
                idAttribute="id"
                entityListType={entityTypes.POLICY}
                getTableColumns={getPolicyTableColumns}
                selectedRowId={selectedRowId}
                search={search}
                page={page}
                checkbox
                tableHeaderComponents={tableHeaderComponents}
                selection={selectedPolicyIds}
                setSelection={setSelectedPolicyIds}
                renderRowActionButtons={renderRowActionButtons}
            />
            <Dialog
                className="w-1/3"
                isOpen={bulkActionPolicyIds.length > 0}
                text={`Are you sure you want to delete ${bulkActionPolicyIds.length} ${pluralize(
                    'policy',
                    bulkActionPolicyIds.length
                )}?`}
                onConfirm={makeDeleteRequest}
                confirmText="Delete"
                onCancel={hideDialog}
                isDestructive
            />
        </>
    );
};

VulnMgmtPolicies.propTypes = {
    ...workflowListPropTypes,
    refreshTrigger: PropTypes.number,
    setRefreshTrigger: PropTypes.func
};
VulnMgmtPolicies.defaultProps = {
    ...workflowListDefaultProps,
    sort: null,
    refreshTrigger: 0,
    setRefreshTrigger: null
};

const mapDispatchToProps = {
    addToast: notificationActions.addNotification,
    removeToast: notificationActions.removeOldestNotification
};

export default connect(
    null,
    mapDispatchToProps
)(VulnMgmtPolicies);
