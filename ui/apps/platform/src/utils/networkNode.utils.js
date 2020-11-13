import flatMap from 'lodash/flatMap';

import { nodeTypes } from 'constants/networkGraph';
import entityTypes from 'constants/entityTypes';
import { filterModes } from 'constants/networkFilterModes';
import { getEdgesFromNode, getClasses } from './networkGraphUtils';

/**
 * Create the cluster node for the network graph
 *
 * @param   {!String} clusterName
 *
 * @return  {!Object}
 */
export const getClusterNode = (clusterName) => {
    const clusterNode = {
        classes: 'cluster',
        data: {
            id: clusterName,
            name: clusterName,
            active: false,
            type: entityTypes.CLUSTER,
        },
    };
    return clusterNode;
};

/**
 * Select out the entity representing external connections in the cluster
 *
 * @param   {!Object[]} data    list of "deployments", without the external entity filtered out
 * @param   {!Object} configObj config object of the current network graph state
 *                              that contains links, filterState, and nodeSideMap,
 *                              networkNodeMap, hoveredNode, and selectedNode
 *
 * @return  {!Object}
 */
export const getExternalEntitiesNode = (data, configObj = {}) => {
    const { hoveredNode, selectedNode, filterState, networkNodeMap } = configObj;

    const externalNode = data.find((datum) => datum?.entity?.type === nodeTypes.EXTERNAL_ENTITIES);

    if (!externalNode) {
        return null;
    }

    const { entity, ...datumProps } = externalNode;
    const entityData = networkNodeMap[entity.id];
    const edges = getEdgesFromNode(configObj);

    const externallyConnected =
        // TODO: figure out how this should be handled in External Entity context
        filterState === filterModes.all
            ? entityData?.active?.externallyConnected
            : externalNode?.externallyConnected;

    const isSelected = !!(selectedNode?.type === nodeTypes.EXTERNAL_ENTITIES);
    const isHovered = !!(hoveredNode?.type === nodeTypes.EXTERNAL_ENTITIES);
    const isBackground = !(!selectedNode && !hoveredNode) && !isHovered && !isSelected;
    // DEPRECATED: const isNonIsolated = getIsNonIsolatedNode(externalNode);
    const isDisallowed =
        filterState !== filterModes.allowed && edges.some((edge) => edge.data.isDisallowed);
    const isExternallyConnected = externallyConnected && filterState !== filterModes.allowed;
    const classes = getClasses({
        active: false, // externalNode.isActive,
        nsSelected: isSelected,
        internet: true,
        disallowed: isDisallowed,
        nsHovered: isHovered,
        background: isBackground,
        nonIsolated: false,
        externallyConnected: isExternallyConnected,
    });

    return {
        data: {
            ...datumProps,
            ...entity,
            id: entity.id,
            name: 'External Entities',
            active: false,
            edges,
            type: nodeTypes.EXTERNAL_ENTITIES,
            parent: null,
        },
        classes,
    };
};

/**
 * Select out the entities representing external connections to CIDR blocks in the cluster
 *
 * @param   {!Object[]} data    list of "deployments", without the external entity filtered out
 * @param   {!Object} configObj config object of the current network graph state
 *                              that contains links, filterState, and nodeSideMap,
 *                              networkNodeMap, hoveredNode, and selectedNode
 *
 * @return  {!Object}
 */
export const getCIDRBlockNodes = (data, configObj = {}) => {
    const { hoveredNode, selectedNode, filterState, networkNodeMap } = configObj;

    const cidrBlocks = data.filter((datum) => datum?.entity?.type === nodeTypes.CIDR_BLOCK);

    if (cidrBlocks.length === 0) {
        return null;
    }

    const cidrBlockNodes = cidrBlocks.map((cidrBlock) => {
        const { entity, ...datumProps } = cidrBlock;
        const entityData = networkNodeMap[entity.id];
        const edges = getEdgesFromNode(configObj);

        const externallyConnected =
            filterState === filterModes.all
                ? entityData?.active?.externallyConnected
                : cidrBlock?.externallyConnected;

        const isSelected = !!(selectedNode?.id === entity.id);
        const isHovered = !!(hoveredNode?.id === entity.id);
        const isBackground = !(!selectedNode && !hoveredNode) && !isHovered && !isSelected;
        // DEPRECATED: const isNonIsolated = getIsNonIsolatedNode(externalNode);
        const isDisallowed =
            filterState !== filterModes.allowed && edges.some((edge) => edge.data.isDisallowed);
        const isExternallyConnected = externallyConnected && filterState !== filterModes.allowed;
        const classes = getClasses({
            active: false,
            nsSelected: isSelected,
            cidrBlock: true,
            disallowed: isDisallowed,
            nsHovered: isHovered,
            background: isBackground,
            nonIsolated: false,
            externallyConnected: isExternallyConnected,
        });

        return {
            data: {
                ...datumProps,
                ...entity,
                id: entity.id,
                cidr: entity.externalSource.cidr,
                name: entity.externalSource.name,
                edges,
                active: false,
                type: nodeTypes.CIDR_BLOCK,
                parent: null,
            },
            classes,
        };
    });
    return cidrBlockNodes;
};

/**
 * Iterates through a list of active nodes and returns nodes with active network policies
 *
 * @param {!Object} networkNodeMap map of nodes by nodeId
 * @returns {!Object[]}
 */
const getActiveNetworkPolicyNodes = (networkNodeMap) => {
    const nodes = [];
    Object.keys(networkNodeMap).forEach((nodeId) => {
        const { active: activeNode, allowed: allowedNode } = networkNodeMap[nodeId];
        const node = { ...activeNode };
        if (allowedNode) {
            node.policyIds = flatMap(allowedNode.policyIds);
        }
        nodes.push(node);
    });
    return nodes;
};

/**
 * Iterates through a list of nodes and returns only links in the same namespace
 *
 * @param {!Object} networkNodeMap map of nodes by nodeId
 * @param {string} filterState current filter state of the network graph
 * @returns {!Object[]}
 */
export const getFilteredNodes = (networkNodeMap, filterState) => {
    const activeNodes = [];
    const allowedNodes = [];
    Object.keys(networkNodeMap).forEach((id) => {
        if (networkNodeMap[id].active) {
            activeNodes.push(networkNodeMap[id].active);
        }
        if (networkNodeMap[id].allowed) {
            allowedNodes.push(networkNodeMap[id].allowed);
        }
    });
    if (filterState !== filterModes.active) {
        return allowedNodes;
    }

    // return as is
    if (!allowedNodes || !activeNodes) {
        return activeNodes;
    }

    return getActiveNetworkPolicyNodes(networkNodeMap);
};
