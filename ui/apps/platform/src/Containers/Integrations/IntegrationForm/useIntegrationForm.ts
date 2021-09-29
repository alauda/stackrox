import { useState } from 'react';
import { useFormik, FormikProps } from 'formik';
import { BaseSchema } from 'yup';

import { IntegrationOptions } from 'services/IntegrationsService';

import useIntegrationActions from '../hooks/useIntegrationActions';

export type FormResponseMessage = {
    message: string;
    isError: boolean;
    responseData?: unknown;
} | null;

export type UseIntegrationForm<T> = {
    initialValues: T;
    validationSchema: BaseSchema | (() => BaseSchema);
};

export type UseIntegrationFormResult<T> = FormikProps<T> & {
    isTesting: boolean;
    onSave: (options?: IntegrationOptions) => void;
    onTest: (options?: IntegrationOptions) => void;
    onCancel: () => void;
    message: FormResponseMessage;
};

function useIntegrationForm<T>({
    initialValues,
    validationSchema,
}: UseIntegrationForm<T>): UseIntegrationFormResult<T> {
    const { onSave, onTest, onCancel } = useIntegrationActions();
    // we will submit the form when clicking "Test" or "Create" so this value will distinguish
    // between the two
    const [isTesting, setIsTesting] = useState(false);
    const [options, setOptions] = useState<IntegrationOptions>({});
    // This message will be displayed in a banner using the response we get from either creating
    // or testing an integration
    const [message, setMessage] = useState<FormResponseMessage>(null);
    const formik = useFormik<T>({
        initialValues,
        onSubmit: (formValues) => {
            if (isTesting) {
                const response = onTest(formValues, options);
                return response;
            }
            const response = onSave(formValues, options);
            return response;
        },
        validationSchema,
        validateOnMount: true,
    });

    const { submitForm } = formik;

    async function onTestHandler(optionsArg = {}) {
        setMessage(null);
        setIsTesting(true);
        setOptions(optionsArg);
        const response = await submitForm();
        setMessage(response);
    }

    async function onSaveHandler(optionsArg = {}) {
        setMessage(null);
        setIsTesting(false);
        setOptions(optionsArg);
        const response = await submitForm();
        setMessage(response);
    }

    return {
        ...formik,
        isTesting,
        onSave: onSaveHandler,
        onTest: onTestHandler,
        onCancel,
        message,
    };
}

export default useIntegrationForm;
