// @flow
import {initializer} from 'sulu-admin-bundle/services';
import userStore from 'sulu-admin-bundle/stores/userStore';
import {translate} from 'sulu-admin-bundle/utils';
import {isSupported, login} from './webauthn';

const loginForm = (): ?HTMLFormElement => {
    const password = document.querySelector('input[type="password"]');
    const form = password && password.closest('form');

    // The reset form has password fields too, but no user name.
    return form && form.querySelector('input:not([type="password"])') ? (form: any) : null;
};

const mount = () => {
    const form = loginForm();
    if (!form || form.querySelector('[data-passkey-login]')) {
        return;
    }

    const wrapper = document.createElement('div');
    wrapper.dataset.passkeyLogin = '';
    wrapper.style.cssText = 'margin-top:16px;text-align:center';

    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = translate('sulu_passkey.login');
    button.style.cssText = 'all:revert;cursor:pointer;background:none;border:1px solid currentColor;'
        + 'border-radius:3px;padding:8px 14px;font:inherit;color:inherit';

    const message = document.createElement('p');
    message.setAttribute('role', 'alert');
    message.style.cssText = 'margin:8px 0 0;font-size:12px';

    button.addEventListener('click', () => {
        message.textContent = '';
        button.disabled = true;

        login()
            .then((response) => {
                // A page that started logged out has no routes yet, and only Sulu's private router can load them. Nothing
                // is open on such a page, so a reload loses nothing.
                if (!initializer.initialized) {
                    window.location.reload();

                    return;
                }

                // Otherwise continue on the open page like Sulu's password login: a reload would throw away unsaved form
                // data, and the browser would ask about it.
                button.disabled = false;

                return userStore.handleLogin(response);
            })
            .catch(() => {
                message.textContent = translate('sulu_passkey.login_failed');
                button.disabled = false;
            });
    });

    wrapper.append(button, message);
    form.append(wrapper);
};

/**
 * Sulu's login form has no extension point, so the button is added to the rendered form from the outside.
 */
export default function mountLoginButton() {
    if (!isSupported()) {
        return;
    }

    new MutationObserver(mount).observe((document.documentElement: any), {childList: true, subtree: true});
}
