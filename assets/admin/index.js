// @flow
import {fieldRegistry} from 'sulu-admin-bundle/containers';
import mountLoginButton from './mountLoginButton';
import Passkeys from './Passkeys';
import UserPasskeys from './UserPasskeys';

fieldRegistry.add('passkeys', Passkeys);
fieldRegistry.add('user_passkeys', UserPasskeys);

mountLoginButton();
