import React from 'react';
import { Link, generatePath } from 'react-router-dom';
import { Button, Flex, FlexItem, List, ListItem, Text, pluralize } from '@patternfly/react-core';
import { ExternalLinkAltIcon, MinusCircleIcon } from '@patternfly/react-icons';

import { vulnerabilitiesWorkloadCvesPath } from 'routePaths';

const vulnerabilitiesWorkloadCveSinglePath = `${vulnerabilitiesWorkloadCvesPath}/cves/:cve`;

export type CveSelectionsProps = {
    cves: { cve: string; summary: string; numAffectedImages: number }[];
    selectedCVEIds: string[];
    onRemove: (cve: string) => void;
};

function CveSelections({ cves, selectedCVEIds, onRemove }: CveSelectionsProps) {
    const onRemoveHandler = (cve: string) => () => {
        onRemove(cve);
    };

    const selectedCVEs = cves.filter((cve) => selectedCVEIds.includes(cve.cve));

    return (
        <List isPlain isBordered>
            {selectedCVEs.map(({ cve, summary, numAffectedImages }) => (
                <ListItem key={cve}>
                    <Flex direction={{ default: 'column' }}>
                        <Flex direction={{ default: 'row' }}>
                            <Text>
                                <Link
                                    target="_blank"
                                    to={generatePath(vulnerabilitiesWorkloadCveSinglePath, {
                                        cve,
                                    })}
                                >
                                    {cve} <ExternalLinkAltIcon className="pf-u-display-inline" />
                                </Link>
                            </Text>
                            <Text>Across {pluralize(numAffectedImages, 'image')}</Text>
                            <FlexItem align={{ default: 'alignRight' }}>
                                <Button
                                    variant="plain"
                                    aria-label="Remove CVE"
                                    onClick={onRemoveHandler(cve)}
                                >
                                    <MinusCircleIcon />
                                </Button>
                            </FlexItem>
                        </Flex>
                        <Text>{summary}</Text>
                    </Flex>
                </ListItem>
            ))}
        </List>
    );
}

export default CveSelections;
