import gql from 'graphql-tag';

export const SUBJECT_WITH_CLUSTER_FRAGMENT = gql`
    fragment subjectWithClusterFields on SubjectWithClusterID {
        id: name
        subject {
            name
            kind
            namespace
        }
        type
        scopedPermissions {
            scope
            permissions {
                key
                values
            }
        }
        clusterAdmin
        roles {
            id
            name
        }
    }
`;

export const SUBJECTS_QUERY = gql`
    query subjects($query: String) {
        subjects(query: $query) {
            ...subjectFields
        }
    }
    fragment subjectFields on Subject {
        subjectWithClusterID {
            ...subjectWithClusterFields
        }
    }
    fragment subjectWithClusterFields on SubjectWithClusterID {
        id: name
        subject {
            name
            kind
            namespace
        }
        type
        clusterAdmin
        roles {
            id
            name
        }
    }
`;

export const SUBJECT_NAME = gql`
    query getSubjectName($id: String!) {
        clusters {
            id
            subject(name: $id) {
                id: name
                subject {
                    name
                }
            }
        }
    }
`;

export const SUBJECT_QUERY = gql`
    query subject($id: String!) {
        clusters {
            id
            subject(name: $id) {
                id: name
                subject {
                    name
                    kind
                    namespace
                }
                type
                scopedPermissions {
                    scope
                    permissions {
                        key
                        values
                    }
                }
                clusterAdmin
                roles {
                    id
                    name
                }
            }
        }
    }
`;
