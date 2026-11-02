# Security Policy

## Supported versions

Security fixes are released for the latest version only. Please check that the issue still occurs on the latest release before reporting it.

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Report it privately via GitHub instead: [Report a vulnerability](https://github.com/actualizer/sulu-passkey/security/advisories/new). Only you and the maintainers can see the report. If you cannot use GitHub, send an email to plugin@actualize.de.

Please include:

- the bundle version and Sulu version
- the steps to reproduce
- what an attacker gains

## What to expect

- An acknowledgement within 7 days.
- Once confirmed, a fix is released as a new version. The advisory is published after that release, crediting you unless you prefer otherwise.

## Scope

In scope:

- Signing in as another user, or signing in without a valid passkey.
- Skipping Sulu's two-factor login without signing in with a passkey.
- Reusing a challenge, or using a passkey on a domain it was not created for.
- Listing or deleting passkeys of another user without the permission `sulu.security.passkeys`, or adding a passkey to another user's account.
- Adding or deleting your own passkey without the confirmation with the password or an existing passkey.
- A session that keeps working after the passkey it was signed in with has been deleted.
- Getting around the rate limits of the passkey login or of the password confirmation.
- WebAuthn payloads or credential data written to logs or exposed in responses.

Out of scope:

- The behaviour described under "What this bundle cannot prevent" and "Limits" in the README, such as Sulu's profile changing the password without the current one, or setups with more than one server without a shared cache, lock and rate limit store.
- Missing configuration described in the README, such as trusted proxies behind a reverse proxy.
- Weaknesses of a browser, an operating system or an authenticator.
- Vulnerabilities in Sulu itself. Please report those to Sulu: <https://github.com/sulu/sulu/security/policy>.
