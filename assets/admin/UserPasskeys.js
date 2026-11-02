// @flow
import React, {Fragment} from 'react';
import {action, observable} from 'mobx';
import {observer} from 'mobx-react';
import {Button, Dialog, Loader} from 'sulu-admin-bundle/components';
import {Requester} from 'sulu-admin-bundle/services';
import userStore from 'sulu-admin-bundle/stores/userStore';
import {translate} from 'sulu-admin-bundle/utils';
import passkeysStyles from './passkeys.scss';
import type {FieldTypeProps} from 'sulu-admin-bundle/types';

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
 * The passkeys of the user being edited. Only deleting is possible here, and it happens right away instead of waiting
 * for the save button of the form. The server decides who may do either, the field just reflects the answer.
 */
@observer
class UserPasskeys extends React.Component<FieldTypeProps<void>> {
    @observable credentials: ?Array<Credential>;
    @observable credentialToDelete: ?Credential;
    @observable deleting: boolean = false;

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

        Requester.delete(`${url}/${credentialToDelete.id}`)
            .then(this.loadCredentials)
            .finally(action(() => {
                this.deleting = false;
                this.credentialToDelete = undefined;
            }));
    };

    renderCredential(credential: Credential) {
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
                    disabled={!!this.props.disabled || this.ownAccount}
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
                        {this.credentials.map((credential) => this.renderCredential(credential))}
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
                </Dialog>
            </Fragment>
        );
    }
}

export default UserPasskeys;
