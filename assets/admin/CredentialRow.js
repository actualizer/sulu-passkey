// @flow
import React from 'react';
import {Button} from 'sulu-admin-bundle/components';
import {translate} from 'sulu-admin-bundle/utils';
import passkeysStyles from './passkeys.scss';

export type Credential = {|
    cloneWarningAt: ?string,
    createdAt: string,
    id: string,
    lastUsedAt: ?string,
    name: string,
|};

type Props = {|
    credential: Credential,
    disabled: boolean,
    onDelete: (credential: Credential) => void,
|};

const formatDate = (value: string): string => new Date(value).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
});

/**
 * One passkey, as the profile and the user form both list it.
 */
export default function CredentialRow({credential, disabled, onDelete}: Props) {
    return (
        <li className={passkeysStyles.credential}>
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
            <Button disabled={disabled} icon="su-trash-alt" onClick={onDelete} skin="link" value={credential}>
                {translate('sulu_admin.delete')}
            </Button>
        </li>
    );
}
