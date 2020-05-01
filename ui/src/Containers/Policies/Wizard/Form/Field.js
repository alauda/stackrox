import React from 'react';
import PropTypes from 'prop-types';
import { FieldArray } from 'redux-form';

import ReduxSelectField from 'Components/forms/ReduxSelectField';
import ReduxTextField from 'Components/forms/ReduxTextField';
import ReduxTextAreaField from 'Components/forms/ReduxTextAreaField';
import ReduxCheckboxField from 'Components/forms/ReduxCheckboxField';
import ReduxMultiSelectField from 'Components/forms/ReduxMultiSelectField';
import ReduxMultiSelectCreatableField from 'Components/forms/ReduxMultiSelectCreatableField';
import ReduxNumericInputField from 'Components/forms/ReduxNumericInputField';
import ReduxToggleField from 'Components/forms/ReduxToggleField';
import ReduxRadioButtonGroupField from 'Components/forms/ReduxRadioButtonGroupField';
import RestrictToScope from './RestrictToScope';
import WhitelistScope from './WhitelistScope';

export default function Field({ field, name }) {
    if (field === undefined) return null;
    // this is to accomodate for recursive Fields (when type is 'group')
    const pathName = field.subpath ? name : `${name}.value`;
    // we use jsonpath for non-policy configuration fields
    const path = name ? pathName : field.jsonpath;
    switch (field.type) {
        case 'text':
            return (
                <ReduxTextField
                    key={path}
                    name={path}
                    disabled={field.disabled}
                    placeholder={field.placeholder}
                />
            );
        case 'checkbox':
            return <ReduxCheckboxField name={path} disabled={field.disabled} />;
        case 'toggle':
            return (
                <ReduxToggleField
                    name={path}
                    key={path}
                    disabled={field.disabled}
                    reverse={field.reverse}
                    className="self-center"
                />
            );
        case 'radioGroup':
            return (
                <ReduxRadioButtonGroupField
                    name={path}
                    key={path}
                    buttons={field.radioButtons}
                    groupClassName="w-full"
                    useBoolean
                />
            );
        case 'select':
            return (
                <ReduxSelectField
                    key={path}
                    name={path}
                    options={field.options}
                    placeholder={field.placeholder}
                    disabled={field.disabled}
                    defaultValue={field.default}
                />
            );
        case 'multiselect':
            return <ReduxMultiSelectField name={path} options={field.options} />;
        case 'multiselect-creatable':
            return <ReduxMultiSelectCreatableField name={path} options={field.options} />;
        case 'textarea':
            return (
                <ReduxTextAreaField
                    name={path}
                    key={path}
                    disabled={field.disabled}
                    placeholder={field.placeholder}
                />
            );
        case 'number':
            return (
                <ReduxNumericInputField
                    key={path}
                    name={path}
                    min={field.min}
                    max={field.max}
                    step={field.step}
                    placeholder={field.placeholder}
                />
            );
        case 'group':
            return field.jsonpaths.map((subField) => {
                const subFieldName = name ? `${name}.${subField.subpath}` : subField.jsonpath;
                return <Field key={subField.jsonpath} name={subFieldName} field={subField} />;
            });
        case 'scope':
            return <FieldArray key={path} name={path} component={RestrictToScope} />;
        case 'whitelistScope':
            return <FieldArray key={path} name={path} component={WhitelistScope} />;
        default:
            throw new Error(`Unknown field type: ${field.type}`);
    }
}

Field.propsTypes = {
    field: PropTypes.shape({
        type: PropTypes.string.isRequired,
    }).isRequired,
    name: PropTypes.string,
};

Field.defaultProps = {
    name: '',
};
