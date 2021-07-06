/* constants specific to Roles */
export const NO_ACCESS = 'NO_ACCESS';
export const READ_ACCESS = 'READ_ACCESS';
export const READ_WRITE_ACCESS = 'READ_WRITE_ACCESS';

export type AccessLevel = 'NO_ACCESS' | 'READ_ACCESS' | 'READ_WRITE_ACCESS';

const defaultRoles = {
    Admin: true,
    Analyst: true,
    'Continuous Integration': true,
    None: true,
    'Sensor Creator': true,
};

export function getIsDefaultRoleName(name: string): boolean {
    return Boolean(defaultRoles[name]);
}

// TODO Delete when backend returns descriptions for default roles and permission sets.
export const defaultRoleDescriptions: Record<string, string> = {
    Admin: 'For users: read and write access for all resources',
    Analyst: 'For users: read-only access for all resources',
    'Continuous Integration': 'For automation: permissions to enforce deployment policies',
    None: 'For users: possible minimum access role in auth providers',
    'Sensor Creator': 'For automation: permissions to create sensors in secured clusters',
};

/* constants specific to Auth Providers */
export const availableAuthProviders = [
    {
        label: 'Auth0',
        value: 'auth0',
    },
    {
        label: 'OpenID Connect',
        value: 'oidc',
    },
    {
        label: 'SAML 2.0',
        value: 'saml',
    },
    {
        label: 'User Certificates',
        value: 'userpki',
    },
    {
        label: 'Google IAP',
        value: 'iap',
    },
];

export const oidcCallbackModes = [
    {
        label: 'Auto-select (recommended)',
        value: 'auto',
    },
    {
        label: 'HTTP POST',
        value: 'post',
    },
    {
        label: 'Fragment',
        value: 'fragment',
    },
    {
        label: 'Query',
        value: 'query',
    },
];

// DEPRECATED, replaced by map for SAC above
export const oidcCallbackValues = {
    auto: 'Auto-select (recommended)',
    post: 'HTTP POST',
    fragment: 'Fragment',
    query: 'Query',
};

export function getAuthProviderLabelByValue(value: string): string {
    return availableAuthProviders.find((e) => e.value === value)?.label ?? '';
}

export const defaultMinimalReadAccessResources = [
    'Alert',
    'Cluster',
    'Config',
    'Deployment',
    'Image',
    'Namespace',
    'NetworkPolicy',
    'NetworkGraph',
    'Node',
    'Policy',
    'Secret',
];

// Default to giving new roles read access to specific resources.
export const defaultNewRolePermissions = defaultMinimalReadAccessResources.reduce(
    (map, resource) => {
        const newMap = map;
        newMap[resource] = READ_ACCESS;
        return newMap;
    },
    {}
);

export const defaultSelectedRole = {
    name: '',
    resourceToAccess: defaultNewRolePermissions,
};
