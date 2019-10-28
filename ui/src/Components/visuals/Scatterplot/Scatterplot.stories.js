import React from 'react';

import { severities } from 'constants/severities';
import severityColorMap from 'constants/severityColors';
import Scatterplot from './Scatterplot';

export default {
    title: 'Scatterplot',
    component: Scatterplot
};

const data = [
    { x: 6, y: 8.7, color: 'var(--caution-400)' },
    { x: 7, y: 4.9, color: 'var(--warning-400)' },
    { x: 43, y: 5.1, color: 'var(--warning-400)' },
    { x: 47, y: 2, color: 'var(--base-400)' },
    { x: 56, y: 8.2, color: 'var(--caution-400)' },
    { x: 59, y: 3.7, color: 'var(--base-400)' },
    { x: 65, y: 8.5, color: 'var(--caution-400)' },
    { x: 71, y: 6.6, color: 'var(--warning-400)' },
    { x: 80, y: 1.6, color: 'var(--base-400)' },
    { x: 81, y: 6.3, color: 'var(--warning-400)' },
    { x: 83, y: 9.1, color: 'var(--alert-400)' }
];
const legendData = [
    { title: 'Low', color: severityColorMap[severities.LOW_SEVERITY] },
    { title: 'Medium', color: severityColorMap[severities.MEDIUM_SEVERITY] },
    { title: 'High', color: severityColorMap[severities.HIGH_SEVERITY] },
    { title: 'Critical', color: severityColorMap[severities.CRITICAL_SEVERITY] }
];

export const withData = () => {
    return (
        <div className="w-full h-64">
            <Scatterplot data={data} legendData={legendData} />
        </div>
    );
};

export const withSetXDomain = () => {
    return (
        <div className="w-full h-64">
            <Scatterplot data={data} lowerX={0} upperX={200} legendData={legendData} />
        </div>
    );
};

export const withSetYDomain = () => {
    return (
        <div className="w-full h-64">
            <Scatterplot data={data} lowerY={0} upperY={20} legendData={legendData} />
        </div>
    );
};

export const withSetXandYDomains = () => {
    return (
        <div className="w-full h-64">
            <Scatterplot
                data={data}
                lowerX={0}
                upperX={150}
                lowerY={0}
                upperY={25}
                legendData={legendData}
            />
        </div>
    );
};
