// @flow
import {Requester} from 'sulu-admin-bundle/services';

export const isSupported = (): boolean => !!window.PublicKeyCredential;

const toBuffer = (value: string): ArrayBuffer => {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4);

    return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0)).buffer;
};

const toBase64Url = (buffer: ArrayBuffer): string => btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const toDescriptors = (items: ?Array<Object>) => (items || []).map((item) => ({...item, id: toBuffer(item.id)}));

const toAssertion = (credential: Object): string => JSON.stringify({
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    response: {
        clientDataJSON: toBase64Url(credential.response.clientDataJSON),
        authenticatorData: toBase64Url(credential.response.authenticatorData),
        signature: toBase64Url(credential.response.signature),
        userHandle: credential.response.userHandle ? toBase64Url(credential.response.userHandle) : null,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
});

const sign = (options: Object): Promise<Object> => navigator.credentials.get({
    publicKey: {
        ...options,
        challenge: toBuffer(options.challenge),
        allowCredentials: toDescriptors(options.allowCredentials),
    },
});

export const login = async () => {
    const {options, challengeId} = await Requester.post('/admin/p/passkey/login/options', {});
    const credential = await sign(options);

    return Requester.post('/admin/p/passkey/login', {challengeId, credential: toAssertion(credential)});
};

export const reauthenticateWithPassword = (password: string) => Requester.post('/admin/passkey/reauth', {password});

export const reauthenticateWithPasskey = async () => {
    const {options, challengeId} = await Requester.post('/admin/passkey/reauth/options', {});
    const credential = await sign(options);

    await Requester.post('/admin/passkey/reauth', {challengeId, credential: toAssertion(credential)});
};

export const register = async (name: string) => {
    const {options, challengeId} = await Requester.post('/admin/passkey/register/options', {});
    const credential: Object = await navigator.credentials.create({
        publicKey: {
            ...options,
            challenge: toBuffer(options.challenge),
            user: {...options.user, id: toBuffer(options.user.id)},
            excludeCredentials: toDescriptors(options.excludeCredentials),
        },
    });

    await Requester.post('/admin/passkey/register', {
        challengeId,
        name,
        credential: JSON.stringify({
            id: credential.id,
            rawId: toBase64Url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: toBase64Url(credential.response.clientDataJSON),
                attestationObject: toBase64Url(credential.response.attestationObject),
                transports: credential.response.getTransports ? credential.response.getTransports() : [],
            },
            clientExtensionResults: credential.getClientExtensionResults(),
        }),
    });
};
