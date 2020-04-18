/**
 * Selectors to interact with react-select
 */

const selectors = {
    input: '.react-select__input > input',
    values: '.react-select__multi-value__label',
    removeValueButton: value =>
        `.react-select__multi-value__label:contains("${value}") + .react-select__multi-value__remove`,
    options: '.react-select__option'
};

export default selectors;
