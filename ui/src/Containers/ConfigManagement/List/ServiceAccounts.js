import React from 'react';
import URLService from 'modules/URLService';
import entityTypes from 'constants/entityTypes';
import { SERVICE_ACCOUNTS as QUERY } from 'queries/serviceAccount';
import { sortValueByLength } from 'sorters/sorters';
import { entityListPropTypes, entityListDefaultprops } from 'constants/entityPageProps';
import { defaultHeaderClassName, defaultColumnClassName } from 'Components/Table';
import queryService from 'modules/queryService';
import pluralize from 'pluralize';
import PermissionCounts from 'Containers/ConfigManagement/Entity/widgets/PermissionCounts';

import List from './List';
import TableCellLink from './Link';

const buildTableColumns = (match, location) => {
    const tableColumns = [
        {
            Header: 'Id',
            headerClassName: 'hidden',
            className: 'hidden',
            accessor: 'id'
        },
        {
            Header: `Service Accounts`,
            headerClassName: `w-1/10 ${defaultHeaderClassName}`,
            className: `w-1/10 ${defaultColumnClassName}`,
            accessor: 'name'
        },
        {
            Header: `Permissions`,
            headerClassName: `w-1/4 ${defaultHeaderClassName}`,
            className: `w-1/4 text-sm ${defaultColumnClassName}`,
            // eslint-disable-next-line
            Cell: ({ original }) => {
                const { scopedPermissions } = original;
                return <PermissionCounts scopedPermissions={scopedPermissions} />;
            },
            id: 'permissions',
            accessor: 'scopedPermissions[0].permissions',
            sortMethod: sortValueByLength
        },
        {
            Header: `Cluster Admin Role`,
            headerClassName: `w-1/10 ${defaultHeaderClassName}`,
            className: `w-1/10 ${defaultColumnClassName}`,
            Cell: ({ original }) => {
                const { clusterAdmin } = original;
                return clusterAdmin ? 'Enabled' : 'Disabled';
            },
            accessor: 'clusterAdmin'
        },
        {
            Header: `Permissions Scope`,
            headerClassName: `w-1/10 ${defaultHeaderClassName}`,
            className: `w-1/10 ${defaultColumnClassName}`,
            Cell: ({ original }) => {
                const { scopedPermissions } = original;
                if (!scopedPermissions.length) return 'No Permissions';
                const result = scopedPermissions
                    .map(({ scope, permissions }) => `${scope} (${permissions.length})`)
                    .join(', ');
                return result;
            },
            id: 'permissionsScope',
            accessor: 'scopedPermissions[0].permissions',
            sortMethod: sortValueByLength
        },
        {
            Header: `Cluster`,
            headerClassName: `w-1/8 ${defaultHeaderClassName}`,
            className: `w-1/8 ${defaultColumnClassName}`,
            accessor: 'clusterName',
            // eslint-disable-next-line
            Cell: ({ original, pdf }) => {
                const { clusterName, clusterId, id } = original;
                const url = URLService.getURL(match, location)
                    .push(id)
                    .push(entityTypes.CLUSTER, clusterId)
                    .url();
                return <TableCellLink pdf={pdf} url={url} text={clusterName} />;
            }
        },
        {
            Header: `Namespace`,
            headerClassName: `w-1/10 ${defaultHeaderClassName}`,
            className: `w-1/10 ${defaultColumnClassName}`,
            accessor: 'namespace',
            // eslint-disable-next-line
            Cell: ({ original, pdf }) => {
                const {
                    id,
                    saNamespace: { metadata }
                } = original;
                if (!metadata) return 'No Matches';
                const { name, id: namespaceId } = metadata;
                const url = URLService.getURL(match, location)
                    .push(id)
                    .push(entityTypes.NAMESPACE, namespaceId)
                    .url();
                return <TableCellLink pdf={pdf} url={url} text={name} />;
            }
        },
        {
            Header: `Roles`,
            headerClassName: `w-1/8 ${defaultHeaderClassName}`,
            className: `w-1/8 ${defaultColumnClassName}`,
            Cell: ({ original, pdf }) => {
                const { id, roles } = original;
                const { length } = roles;
                if (!length) return 'No Matches';
                const url = URLService.getURL(match, location)
                    .push(id)
                    .push(entityTypes.ROLE)
                    .url();
                if (length > 1)
                    return (
                        <TableCellLink
                            pdf={pdf}
                            url={url}
                            text={`${length} ${pluralize('Roles', length)}`}
                        />
                    );
                return original.roles[0].name;
            },
            accessor: 'roles',
            sortMethod: sortValueByLength
        }
    ];
    return tableColumns;
};

const createTableRows = data => data.results;

const ServiceAccounts = ({
    match,
    location,
    className,
    selectedRowId,
    onRowClick,
    query,
    data
}) => {
    const tableColumns = buildTableColumns(match, location);
    const queryText = queryService.objectToWhereClause(query);
    const variables = queryText ? { query: queryText } : null;
    return (
        <List
            className={className}
            query={QUERY}
            variables={variables}
            entityType={entityTypes.SERVICE_ACCOUNT}
            tableColumns={tableColumns}
            createTableRows={createTableRows}
            onRowClick={onRowClick}
            selectedRowId={selectedRowId}
            idAttribute="id"
            defaultSorted={[
                {
                    id: 'scopedPermissions[0].permissions',
                    desc: true
                }
            ]}
            data={data}
        />
    );
};
ServiceAccounts.propTypes = entityListPropTypes;
ServiceAccounts.defaultProps = entityListDefaultprops;

export default ServiceAccounts;
