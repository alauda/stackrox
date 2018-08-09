import React, { Component } from 'react';
import { connect } from 'react-redux';
import PropTypes from 'prop-types';
import * as Icon from 'react-feather';
import { createStructuredSelector } from 'reselect';

import { actions } from 'reducers/apitokens';
import { selectors } from 'reducers';

import ComponentTable from 'Components/Table';
import Modal from 'Components/Modal';
import Panel from 'Components/Panel';
import PanelButton from 'Components/PanelButton';

import APITokenForm from './APITokenForm';
import APITokenDetails from './APITokenDetails';

class APITokensModal extends Component {
    static propTypes = {
        tokens: PropTypes.arrayOf(
            PropTypes.shape({
                id: PropTypes.string.isRequired,
                name: PropTypes.string.isRequired,
                role: PropTypes.string.isRequired
            })
        ).isRequired,
        tokenGenerationWizardOpen: PropTypes.bool.isRequired,
        onRequestClose: PropTypes.func.isRequired,
        startTokenGenerationWizard: PropTypes.func.isRequired,
        closeTokenGenerationWizard: PropTypes.func.isRequired,
        generateAPIToken: PropTypes.func.isRequired,
        revokeAPITokens: PropTypes.func.isRequired,
        currentGeneratedToken: PropTypes.string,
        currentGeneratedTokenMetadata: PropTypes.shape({
            name: PropTypes.string.isRequired,
            role: PropTypes.string.isRequired
        })
    };

    static defaultProps = {
        currentGeneratedToken: '',
        currentGeneratedTokenMetadata: null
    };

    static tableColumnDescriptors = [
        { key: 'name', label: 'Name' },
        { key: 'role', label: 'Role' }
    ];

    state = {
        checkedTokenIds: [],
        selectedTokenId: null
    };

    onRowClick = row => {
        this.setState({ selectedTokenId: row.id });
    };

    onRowChecked = selectedRows => this.setState({ checkedTokenIds: selectedRows });

    onSubmit = () => {
        this.props.generateAPIToken();
    };

    revokeTokens = () => {
        if (this.state.checkedTokenIds.length === 0) return;
        this.props.revokeAPITokens(this.state.checkedTokenIds);
    };

    unSelectRow = () => {
        this.setState({ selectedTokenId: null });
    };

    closeModal = () => {
        this.props.closeTokenGenerationWizard();
        this.props.onRequestClose();
    };

    openForm = () => {
        this.props.startTokenGenerationWizard();
    };

    closeForm = () => {
        this.props.closeTokenGenerationWizard();
    };

    showTokenGenerationDetails = () =>
        this.props.currentGeneratedToken && this.props.currentGeneratedTokenMetadata;

    renderPanelButtons = () => (
        <React.Fragment>
            <PanelButton
                icon={<Icon.Slash className="h-4 w-4" />}
                text="Revoke"
                className="btn btn-danger"
                onClick={this.revokeTokens}
                disabled={this.state.checkedTokenIds.length === 0}
            />
            <PanelButton
                icon={<Icon.Plus className="h-4 w-4" />}
                text="Generate"
                className="btn btn-success"
                onClick={this.openForm}
                disabled={
                    this.props.tokenGenerationWizardOpen || this.state.selectedTokenId !== null
                }
            />
        </React.Fragment>
    );

    renderHeader = () => (
        <header className="flex items-center w-full p-4 bg-primary-500 text-white uppercase">
            <span className="flex flex-1">Configure API Tokens</span>
            <Icon.X className="h-4 w-4 cursor-pointer" onClick={this.closeModal} />
        </header>
    );

    renderTable = () => (
        <Panel header="API Tokens" buttons={this.renderPanelButtons()}>
            <ComponentTable
                columns={APITokensModal.tableColumnDescriptors}
                rows={this.props.tokens}
                checkboxes
                onRowClick={this.onRowClick}
                onRowChecked={this.onRowChecked}
                messageIfEmpty="No API Tokens Generated"
            />
        </Panel>
    );

    renderForm = () => {
        if (!this.props.tokenGenerationWizardOpen) {
            return null;
        }
        if (this.showTokenGenerationDetails()) {
            return null;
        }

        const buttons = (
            <PanelButton
                icon={<Icon.Save className="h-4 w-4" />}
                text="Generate"
                className="btn btn-success"
                onClick={this.onSubmit}
            />
        );

        return (
            <Panel header="Generate API Token" onClose={this.closeForm} buttons={buttons}>
                <APITokenForm />
            </Panel>
        );
    };

    renderDetails = () => {
        if (this.showTokenGenerationDetails()) {
            const { currentGeneratedToken, currentGeneratedTokenMetadata } = this.props;
            return (
                <Panel header="Generated Token" onClose={this.closeForm}>
                    <APITokenDetails
                        token={currentGeneratedToken}
                        metadata={currentGeneratedTokenMetadata}
                    />
                </Panel>
            );
        }
        if (this.state.selectedTokenId) {
            const selectedTokenMetadata = this.props.tokens.find(
                ({ id }) => id === this.state.selectedTokenId
            );
            if (selectedTokenMetadata) {
                return (
                    <Panel header="Token Details" onClose={this.unSelectRow}>
                        <APITokenDetails metadata={selectedTokenMetadata} />
                    </Panel>
                );
            }
        }
        return null;
    };

    render() {
        return (
            <Modal
                isOpen
                onRequestClose={this.props.onRequestClose}
                className="w-full lg:w-5/6 h-full"
            >
                {this.renderHeader()}
                <div className="flex flex-1 w-full bg-white">
                    {this.renderTable()}
                    {this.renderForm()}
                    {this.renderDetails()}
                </div>
            </Modal>
        );
    }
}

const mapStateToProps = createStructuredSelector({
    tokenGenerationWizardOpen: selectors.tokenGenerationWizardOpen,
    currentGeneratedToken: selectors.getCurrentGeneratedToken,
    currentGeneratedTokenMetadata: selectors.getCurrentGeneratedTokenMetadata
});

const mapDispatchToProps = {
    startTokenGenerationWizard: actions.startTokenGenerationWizard,
    closeTokenGenerationWizard: actions.closeTokenGenerationWizard,
    generateAPIToken: actions.generateAPIToken.request,
    revokeAPITokens: actions.revokeAPITokens
};

export default connect(mapStateToProps, mapDispatchToProps)(APITokensModal);
