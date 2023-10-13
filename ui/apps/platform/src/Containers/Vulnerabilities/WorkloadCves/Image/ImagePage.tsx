import React, { ReactNode } from 'react';
import {
    Breadcrumb,
    BreadcrumbItem,
    Bullseye,
    ClipboardCopy,
    Divider,
    Flex,
    PageSection,
    Skeleton,
    Tab,
    Tabs,
    TabsComponent,
    TabTitleText,
    Title,
} from '@patternfly/react-core';
import { ExclamationCircleIcon } from '@patternfly/react-icons';
import { useParams } from 'react-router-dom';
import { gql, useQuery } from '@apollo/client';

import BreadcrumbItemLink from 'Components/BreadcrumbItemLink';
import PageTitle from 'Components/PageTitle';
import useURLStringUnion from 'hooks/useURLStringUnion';
import EmptyStateTemplate from 'Components/PatternFly/EmptyStateTemplate';
import { getAxiosErrorMessage } from 'utils/responseErrorUtils';
import ImagePageVulnerabilities from './ImagePageVulnerabilities';
import ImagePageResources from './ImagePageResources';
import { detailsTabValues } from '../types';
import { getOverviewCvesPath } from '../searchUtils';
import ImageDetailBadges, {
    ImageDetails,
    imageDetailsFragment,
} from '../components/ImageDetailBadges';

const workloadCveOverviewImagePath = getOverviewCvesPath({
    vulnerabilityState: 'OBSERVED',
    entityTab: 'Image',
});

export const imageDetailsQuery = gql`
    ${imageDetailsFragment}
    query getImageDetails($id: ID!) {
        image(id: $id) {
            id
            name {
                registry
                remote
                tag
            }
            ...ImageDetails
        }
    }
`;

function ImagePage() {
    const { imageId } = useParams();
    const { data, error } = useQuery<
        {
            image: {
                id: string;
                name: {
                    registry: string;
                    remote: string;
                    tag: string;
                } | null;
            } & ImageDetails;
        },
        {
            id: string;
        }
    >(imageDetailsQuery, {
        variables: { id: imageId },
    });
    const [activeTabKey, setActiveTabKey] = useURLStringUnion('detailsTab', detailsTabValues);

    const imageData = data && data.image;
    const imageName = imageData?.name
        ? `${imageData.name.registry}/${imageData.name.remote}:${imageData.name.tag}`
        : 'NAME UNKNOWN';

    let mainContent: ReactNode | null = null;

    if (error) {
        mainContent = (
            <PageSection variant="light">
                <Bullseye>
                    <EmptyStateTemplate
                        title={getAxiosErrorMessage(error)}
                        headingLevel="h2"
                        icon={ExclamationCircleIcon}
                        iconClassName="pf-u-danger-color-100"
                    />
                </Bullseye>
            </PageSection>
        );
    } else {
        const sha = imageData?.id;
        mainContent = (
            <>
                <PageSection variant="light">
                    {imageData ? (
                        <Flex
                            direction={{ default: 'column' }}
                            alignItems={{ default: 'alignItemsFlexStart' }}
                        >
                            <Title headingLevel="h1" className="pf-u-m-0">
                                {imageName}
                            </Title>
                            {sha && (
                                <ClipboardCopy
                                    hoverTip="Copy SHA"
                                    clickTip="Copied!"
                                    variant="inline-compact"
                                    className="pf-u-display-inline-flex pf-u-align-items-center pf-u-mt-sm pf-u-mb-md pf-u-font-size-sm"
                                >
                                    {sha}
                                </ClipboardCopy>
                            )}
                            <ImageDetailBadges imageData={imageData} />
                        </Flex>
                    ) : (
                        <Flex
                            direction={{ default: 'column' }}
                            spaceItems={{ default: 'spaceItemsXs' }}
                            className="pf-u-w-50"
                        >
                            <Skeleton screenreaderText="Loading image name" fontSize="2xl" />
                            <Skeleton screenreaderText="Loading image metadata" fontSize="sm" />
                        </Flex>
                    )}
                </PageSection>
                <PageSection
                    className="pf-u-display-flex pf-u-flex-direction-column pf-u-flex-grow-1"
                    padding={{ default: 'noPadding' }}
                >
                    <Tabs
                        activeKey={activeTabKey}
                        onSelect={(e, key) => setActiveTabKey(key)}
                        component={TabsComponent.nav}
                        className="pf-u-pl-md pf-u-background-color-100"
                        mountOnEnter
                        unmountOnExit
                    >
                        <Tab
                            className="pf-u-display-flex pf-u-flex-direction-column pf-u-flex-grow-1"
                            eventKey="Vulnerabilities"
                            title={<TabTitleText>Vulnerabilities</TabTitleText>}
                        >
                            <ImagePageVulnerabilities imageId={imageId} />
                        </Tab>
                        <Tab
                            className="pf-u-display-flex pf-u-flex-direction-column pf-u-flex-grow-1"
                            eventKey="Resources"
                            title={<TabTitleText>Resources</TabTitleText>}
                        >
                            <ImagePageResources imageId={imageId} />
                        </Tab>
                    </Tabs>
                </PageSection>
            </>
        );
    }

    return (
        <>
            <PageTitle title={`Workload CVEs - Image ${imageData ? imageName : ''}`} />
            <PageSection variant="light" className="pf-u-py-md">
                <Breadcrumb>
                    <BreadcrumbItemLink to={workloadCveOverviewImagePath}>
                        Images
                    </BreadcrumbItemLink>
                    {!error && (
                        <BreadcrumbItem isActive>
                            {imageData ? (
                                imageName
                            ) : (
                                <Skeleton screenreaderText="Loading image name" width="200px" />
                            )}
                        </BreadcrumbItem>
                    )}
                </Breadcrumb>
            </PageSection>
            <Divider component="div" />
            {mainContent}
        </>
    );
}

export default ImagePage;
