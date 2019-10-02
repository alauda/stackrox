import React from 'react';
import { times, daysOfWeek } from './Schedule';

const tableColumnDescriptor = Object.freeze({
    authProviders: {
        oidc: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'config.issuer', Header: 'Issuer' }
        ],
        auth0: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'config.issuer', Header: 'Auth0 Tenant' }
        ],
        saml: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'config.idp_issuer', Header: 'Issuer' }
        ]
    },
    notifiers: {
        slack: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'labelDefault', Header: 'Default Webhook', className: 'word-break' },
            { accessor: 'labelKey', Header: 'Webhook Label Key' }
        ],
        jira: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'labelDefault', Header: 'Default Project' },
            { accessor: 'labelKey', Header: 'Project Label Key' },
            {
                accessor: 'jira.url',
                keyValueFunc: url => (
                    <a href={url} target="_blank" rel="noopener noreferrer">
                        {url}
                    </a>
                ),
                Header: 'URL'
            }
        ],
        email: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'labelDefault', Header: 'Default Recipient' },
            { accessor: 'labelKey', Header: 'Recipient Label Key' },
            { accessor: 'email.server', Header: 'Server' }
        ],
        cscc: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'cscc.sourceId', Header: 'Google Cloud SCC Source ID' }
        ],
        splunk: [
            { accessor: 'name', Header: 'Name' },
            {
                accessor: 'splunk.httpEndpoint',
                keyValueFunc: url => (
                    <a href={url} target="_blank" rel="noopener noreferrer">
                        {url}
                    </a>
                ),
                Header: 'URL'
            },
            { accessor: 'splunk.truncate', Header: 'HEC Truncate Limit (optional)' }
        ],
        pagerduty: [{ accessor: 'name', Header: 'Name' }],
        generic: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'generic.endpoint', Header: 'Endpoint' }
        ],
        sumologic: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'sumologic.httpSourceAddress', Header: 'HTTP Collector Source Address' },
            {
                Header: 'Skip TLS Certificate Verification',
                Cell: ({ original }) => (original.skipTLSVerify ? 'Yes (Insecure)' : 'No (Secure)')
            }
        ]
    },
    imageIntegrations: {
        docker: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'docker.endpoint', Header: 'Endpoint' },
            { accessor: 'docker.username', Header: 'Username' },
            {
                accessor: 'autogenerated',
                Header: 'Autogenerated',
                Cell: ({ original }) => (original.autogenerated ? 'True' : 'False')
            }
        ],
        tenable: [{ accessor: 'name', Header: 'Name' }],
        dtr: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'dtr.endpoint', Header: 'Endpoint' },
            { accessor: 'dtr.username', Header: 'Username' }
        ],
        artifactory: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'docker.endpoint', Header: 'Endpoint' },
            { accessor: 'docker.username', Header: 'Username' }
        ],
        quay: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'quay.endpoint', Header: 'Endpoint' }
        ],
        clair: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'clair.endpoint', Header: 'Endpoint' }
        ],
        scanner: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'scannerv2.endpoint', Header: 'Endpoint' }
        ],
        clairify: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'clairify.endpoint', Header: 'Endpoint' }
        ],
        google: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'google.endpoint', Header: 'Endpoint' }
        ],
        ecr: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'ecr.registryId', Header: 'Registry ID' },
            { accessor: 'ecr.region', Header: 'Region' }
        ],
        nexus: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'docker.endpoint', Header: 'Endpoint' },
            { accessor: 'docker.username', Header: 'Username' }
        ],
        azure: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'docker.endpoint', Header: 'Endpoint' },
            { accessor: 'docker.username', Header: 'Username' }
        ],
        anchore: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'anchore.endpoint', Header: 'Endpoint' },
            { accessor: 'anchore.username', Header: 'Username' }
        ],
        ibm: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'ibm.endpoint', Header: 'Endpoint' }
        ],
        rhel: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'docker.endpoint', Header: 'Endpoint' },
            { accessor: 'docker.username', Header: 'Username' }
        ]
    },
    backups: {
        s3: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 's3.bucket', Header: 'Bucket' },
            {
                id: 'schedule',
                accessor: data => {
                    const { schedule } = data;
                    if (schedule.weekly) {
                        return `Weekly on ${daysOfWeek[schedule.weekly.day]} @ ${
                            times[schedule.hour]
                        } UTC`;
                    }
                    return `Daily @ ${times[schedule.hour]} UTC`;
                },
                Header: 'Schedule'
            }
        ]
    },
    authPlugins: {
        scopedAccess: [
            { accessor: 'name', Header: 'Name' },
            { accessor: 'endpointConfig.endpoint', Header: 'Endpoint' }
        ]
    }
});

export default tableColumnDescriptor;
