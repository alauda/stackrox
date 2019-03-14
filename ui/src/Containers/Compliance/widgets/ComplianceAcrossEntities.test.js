import React from 'react';
import { mount } from 'enzyme';
import { MockedProvider } from 'react-apollo/test-utils';
import { Query } from 'react-apollo';
import getRouterOptions from 'constants/routerOptions';
import entityTypes from 'constants/entityTypes';

import { AGGREGATED_RESULTS } from 'queries/controls';
import ComplianceAcrossEntities from './ComplianceAcrossEntities';

const getMock = entityType => [
    {
        request: {
            query: AGGREGATED_RESULTS,
            variables: {
                groupBy: [entityTypes.STANDARD, entityType],
                unit: entityType
            }
        }
    }
];

const checkQueryForElement = (element, entityType) => {
    const queryProps = element.find(Query).props();
    const queryName = queryProps.query.definitions[0].name.value;
    const queryVars = queryProps.variables;
    expect(queryName === 'getAggregatedResults').toBe(true);
    expect(queryVars.groupBy).toEqual(['STANDARD', entityType]);
    expect(queryVars.unit === entityType).toBe(true);
};

const testQueryForEntityType = entityType => {
    const mock = getMock(entityType);
    const element = mount(
        <MockedProvider mocks={mock} addTypename={false}>
            <ComplianceAcrossEntities entityType={entityType} />
        </MockedProvider>,
        getRouterOptions(jest.fn())
    );

    checkQueryForElement(element, entityType);
};

it('renders for Nodes in Compliance', () => {
    testQueryForEntityType(entityTypes.NODE);
});

it('renders for Namespaces in Compliance', () => {
    testQueryForEntityType(entityTypes.NAMESPACE);
});

it('renders for Clusters in Compliance', () => {
    testQueryForEntityType(entityTypes.CLUSTER);
});
