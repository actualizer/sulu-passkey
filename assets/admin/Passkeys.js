// @flow
import React from 'react';
import {action, observable} from 'mobx';
import {observer} from 'mobx-react';
import {Button, Dialog, Input, Loader, Overlay} from 'sulu-admin-bundle/components';
import {Requester} from 'sulu-admin-bundle/services';
import {translate} from 'sulu-admin-bundle/utils';
import passkeysStyles from './passkeys.scss';
import {isSupported, reauthenticateWithPasskey, reauthenticateWithPassword, register} from './webauthn';
import type {FieldTypeProps} from 'sulu-admin-bundle/types';

const CREDENTIALS_URL = '/admin/passkey/credentials';

type Credential = {|
    createdAt: string,
    id: string,
    cloneWarningAt: ?string,
    lastUsedAt: ?string,
    name: string,
|};

const formatDate = (value: string): string => new Date(value).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
});

/**
 * The passkeys of the signed-in user. Like the two-factor setup, this changes the account right away instead of
 * waiting for the save button of the profile form, so the field never touches the form data.
 */
@observer
class Passkeys extends React.Component<FieldTypeProps<void>> {
    @observable credentials: ?Array<Credential>;
    @observable addOverlayOpen: boolean = false;
    @observable name: ?string;
    @observable password: ?string;
    @observable adding: boolean = false;
    @observable addFailed: boolean = false;
    @observable credentialToDelete: ?Credential;
    @observable deleting: boolean = false;
    @observable deletePassword: ?string;
    @observable deleteFailed: boolean = false;

    root: ?HTMLElement;

    componentDidMount() {
        this.loadCredentials();
    }

    loadCredentials = () => Requester.get(CREDENTIALS_URL)
        .then(action((response) => {
            this.credentials = response.credentials;
        }));

    @action handleAddClick = () => {
        this.name = undefined;
        this.password = undefined;
        this.addFailed = false;
        this.addOverlayOpen = true;
    };

    @action handleAddClose = () => {
        this.addOverlayOpen = false;
    };

    @action handleNameChange = (name: ?string) => {
        this.name = name;
    };

    @action handlePasswordChange = (password: ?string) => {
        this.password = password;
    };

    handleAddConfirm = () => this.enroll(() => reauthenticateWithPassword(this.password || ''));

    handleConfirmWithPasskey = () => this.enroll(reauthenticateWithPasskey);

    // The server only opens an enrollment after a fresh proof that this is still the account's owner.
    @action enroll = (reauthenticate: () => Promise<mixed>) => {
        this.adding = true;
        this.addFailed = false;

        reauthenticate()
            .then(() => register(this.name || ''))
            .then(this.loadCredentials)
            .then(action(() => {
                this.adding = false;
                this.password = undefined;
                this.addOverlayOpen = false;
            }))
            .catch(action(() => {
                this.adding = false;
                this.password = undefined;
                this.addFailed = true;
            }));
    };

    @action handleDeleteClick = (credential: Credential) => {
        this.credentialToDelete = credential;
        this.deletePassword = undefined;
        this.deleteFailed = false;
    };

    @action handleDeleteCancel = () => {
        this.credentialToDelete = undefined;
        this.deletePassword = undefined;
    };

    @action handleDeletePasswordChange = (password: ?string) => {
        this.deletePassword = password;
    };

    handleDeleteConfirm = () => this.delete(() => reauthenticateWithPassword(this.deletePassword || ''));

    handleDeleteWithPasskey = () => this.delete(reauthenticateWithPasskey);

    @action delete = (reauthenticate: () => Promise<mixed>) => {
        const {credentialToDelete} = this;
        if (!credentialToDelete) {
            return;
        }

        this.deleting = true;
        this.deleteFailed = false;

        reauthenticate()
            .then(() => Requester.delete(`${CREDENTIALS_URL}/${credentialToDelete.id}`))
            .then(
                action(() => {
                    this.deleting = false;
                    this.deletePassword = undefined;
                    this.credentialToDelete = undefined;
                    this.credentials = (this.credentials || []).filter(({id}) => id !== credentialToDelete.id);

                    // Not part of the deletion: deleting the passkey of this session ends the session, so the list answers
                    // 401 and Sulu shows its login, as for an expired session. That login sits below the profile overlay,
                    // so close it. Never reload here: the browser would ask about unsaved data, which this way survives
                    // the new login.
                    this.loadCredentials().catch((response) => {
                        if (response && response.status === 401) {
                            this.closeProfileOverlay();
                        }
                    });
                }),
                action(() => {
                    this.deleting = false;
                    this.deletePassword = undefined;
                    this.deleteFailed = true;
                })
            );
    };

    /**
     * Sulu keeps the state of this overlay private, so this uses its close icon. The Escape key is no option: closing an
     * inner overlay, like the one adding a passkey, unbinds it for the outer one.
     */
    closeProfileOverlay() {
        const article = this.root ? this.root.closest('article') : undefined;
        const closeIcon = article && article.parentElement
            ? article.parentElement.querySelector('header .su-times')
            : undefined;

        if (closeIcon instanceof HTMLElement) {
            closeIcon.click();
        }
    }

    setRoot = (root: ?HTMLElement) => {
        this.root = root;
    };

    renderCredential(credential: Credential) {
        const {disabled} = this.props;

        return (
            <li className={passkeysStyles.credential} key={credential.id}>
                <div className={passkeysStyles.details}>
                    <div className={passkeysStyles.name}>{credential.name}</div>
                    <div className={passkeysStyles.meta}>
                        {translate('sulu_passkey.created_at', {date: formatDate(credential.createdAt)})}
                        {' · '}
                        {credential.lastUsedAt
                            ? translate('sulu_passkey.last_used_at', {date: formatDate(credential.lastUsedAt)})
                            : translate('sulu_passkey.never_used')
                        }
                    </div>
                    {credential.cloneWarningAt &&
                        <div className={passkeysStyles.error}>
                            {translate('sulu_passkey.clone_warning', {date: formatDate(credential.cloneWarningAt)})}
                        </div>
                    }
                </div>
                <Button
                    disabled={!!disabled}
                    icon="su-trash-alt"
                    onClick={this.handleDeleteClick}
                    skin="link"
                    value={credential}
                >
                    {translate('sulu_admin.delete')}
                </Button>
            </li>
        );
    }

    render() {
        const {disabled} = this.props;

        if (!this.credentials) {
            return <Loader size={24} />;
        }

        return (
            <div ref={this.setRoot}>
                {this.credentials.length === 0
                    ? <p className={passkeysStyles.empty}>{translate('sulu_passkey.none')}</p>
                    : <ul className={passkeysStyles.list}>
                        {this.credentials.map((credential) => this.renderCredential(credential))}
                    </ul>
                }
                {isSupported()
                    ? <Button disabled={!!disabled} icon="su-plus" onClick={this.handleAddClick} skin="link">
                        {translate('sulu_passkey.add')}
                    </Button>
                    : <p className={passkeysStyles.empty}>{translate('sulu_passkey.unsupported')}</p>
                }
                <Overlay
                    confirmDisabled={!this.name || !this.password}
                    confirmLoading={this.adding}
                    confirmText={translate('sulu_passkey.add')}
                    onClose={this.handleAddClose}
                    onConfirm={this.handleAddConfirm}
                    open={this.addOverlayOpen}
                    size="small"
                    title={translate('sulu_passkey.add')}
                >
                    <div className={passkeysStyles.setup}>
                        <p className={passkeysStyles.hint}>{translate('sulu_passkey.name_hint')}</p>
                        <Input maxCharacters={120} onChange={this.handleNameChange} value={this.name} />
                        <p className={passkeysStyles.hint}>{translate('sulu_passkey.password_hint')}</p>
                        <Input
                            onChange={this.handlePasswordChange}
                            placeholder={translate('sulu_passkey.password')}
                            type="password"
                            value={this.password}
                        />
                        {this.credentials.length > 0 &&
                            <Button
                                disabled={!this.name || this.adding}
                                onClick={this.handleConfirmWithPasskey}
                                skin="link"
                            >
                                {translate('sulu_passkey.confirm_with_passkey')}
                            </Button>
                        }
                        {this.addFailed && <p className={passkeysStyles.error}>{translate('sulu_passkey.add_failed')}</p>}
                    </div>
                </Overlay>
                <Dialog
                    cancelText={translate('sulu_admin.cancel')}
                    confirmDisabled={!this.deletePassword}
                    confirmLoading={this.deleting}
                    confirmText={translate('sulu_admin.delete')}
                    onCancel={this.handleDeleteCancel}
                    onConfirm={this.handleDeleteConfirm}
                    open={!!this.credentialToDelete}
                    title={translate('sulu_passkey.delete')}
                >
                    {translate('sulu_passkey.delete_warning', {
                        name: this.credentialToDelete ? this.credentialToDelete.name : '',
                    })}
                    <p className={passkeysStyles.hint}>{translate('sulu_passkey.password_hint')}</p>
                    <Input
                        onChange={this.handleDeletePasswordChange}
                        placeholder={translate('sulu_passkey.password')}
                        type="password"
                        value={this.deletePassword}
                    />
                    {this.credentials.length > 0 &&
                        <Button disabled={this.deleting} onClick={this.handleDeleteWithPasskey} skin="link">
                            {translate('sulu_passkey.confirm_with_passkey')}
                        </Button>
                    }
                    {this.deleteFailed && <p className={passkeysStyles.error}>{translate('sulu_passkey.delete_failed')}</p>}
                </Dialog>
            </div>
        );
    }
}

export default Passkeys;
