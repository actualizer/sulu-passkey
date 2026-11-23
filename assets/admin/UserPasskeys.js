// @flow
import React, {Fragment} from 'react';
import {action, observable} from 'mobx';
import {observer} from 'mobx-react';
import {Dialog, Loader} from 'sulu-admin-bundle/components';
import {Requester} from 'sulu-admin-bundle/services';
import userStore from 'sulu-admin-bundle/stores/userStore';
import {translate} from 'sulu-admin-bundle/utils';
import CredentialRow from './CredentialRow';
import passkeysStyles from './passkeys.scss';
import type {FieldTypeProps} from 'sulu-admin-bundle/types';
import type {Credential} from './CredentialRow';

/**
 * The passkeys of the user being edited. Only deleting is possible here, and it happens right away instead of waiting
 * for the save button of the form. The server decides who may do either, the field just reflects the answer.
 */
@observer
class UserPasskeys extends React.Component<FieldTypeProps<void>> {
    @observable credentials: ?Array<Credential>;
    @observable credentialToDelete: ?Credential;
    @observable deleting: boolean = false;
    @observable deleteFailed: boolean = false;

    get url(): ?string {
        const userId = this.props.formInspector.getValueByPath('/id');

        return userId ? `/admin/passkey/users/${String(userId)}/credentials` : undefined;
    }

    // The server refuses this field for your own account: the profile asks for a confirmation, this field does not.
    get ownAccount(): boolean {
        return !!userStore.user && userStore.user.id === this.props.formInspector.getValueByPath('/id');
    }

    componentDidMount() {
        this.loadCredentials();
    }

    loadCredentials = () => {
        const {url} = this;
        if (!url) {
            return Promise.resolve();
        }

        return Requester.get(url).then(action((response) => {
            this.credentials = response.credentials;
        }));
    };

    @action handleDeleteClick = (credential: Credential) => {
        this.credentialToDelete = credential;
        this.deleteFailed = false;
    };

    @action handleDeleteCancel = () => {
        this.credentialToDelete = undefined;
    };

    @action handleDeleteConfirm = () => {
        const {credentialToDelete, url} = this;
        if (!credentialToDelete || !url) {
            return;
        }

        this.deleting = true;
        this.deleteFailed = false;

        Requester.delete(`${url}/${credentialToDelete.id}`)
            .then(this.loadCredentials)
            .then(action(() => {
                this.deleting = false;
                this.credentialToDelete = undefined;
            }))
            // The dialog stays open with the reason, instead of closing as if the passkey were gone.
            .catch(action(() => {
                this.deleting = false;
                this.deleteFailed = true;
            }));
    };

    render() {
        if (!this.url) {
            return <p className={passkeysStyles.empty}>{translate('sulu_passkey.none')}</p>;
        }

        if (!this.credentials) {
            return <Loader size={24} />;
        }

        return (
            <Fragment>
                {this.credentials.length === 0
                    ? <p className={passkeysStyles.empty}>{translate('sulu_passkey.none')}</p>
                    : <ul className={passkeysStyles.list}>
                        {this.credentials.map((credential) => (
                            <CredentialRow
                                credential={credential}
                                disabled={!!this.props.disabled || this.ownAccount}
                                key={credential.id}
                                onDelete={this.handleDeleteClick}
                            />
                        ))}
                    </ul>
                }
                {this.ownAccount && <p className={passkeysStyles.empty}>{translate('sulu_passkey.user_own_hint')}</p>}
                <Dialog
                    cancelText={translate('sulu_admin.cancel')}
                    confirmLoading={this.deleting}
                    confirmText={translate('sulu_admin.delete')}
                    onCancel={this.handleDeleteCancel}
                    onConfirm={this.handleDeleteConfirm}
                    open={!!this.credentialToDelete}
                    title={translate('sulu_passkey.delete')}
                >
                    {translate('sulu_passkey.user_delete_warning', {
                        name: this.credentialToDelete ? this.credentialToDelete.name : '',
                    })}
                    {this.deleteFailed && <p className={passkeysStyles.error}>{translate('sulu_passkey.delete_failed')}</p>}
                </Dialog>
            </Fragment>
        );
    }
}

export default UserPasskeys;
