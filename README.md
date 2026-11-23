# Sulu Passkey

Passkey (WebAuthn) login for the [Sulu](https://sulu.io) admin, managed in the user's profile.

> **Node is needed on every Sulu update.** This bundle adds JavaScript to the admin, so the admin can no longer use the
> prebuilt download: `sulu:admin:update-build` builds it itself and needs Node and npm wherever you run it. The same goes
> for updates of this bundle. Run it interactively and keep your `package.json`, see [Building the admin](#building-the-admin).

## What it does

- A "Sign in with passkey" button on Sulu's login form.
- A passkey login skips Sulu's e-mail code. The server requires user verification, but it can only take the
  authenticator's word for it, see [What this bundle cannot prevent](#what-this-bundle-cannot-prevent).
- Users add and delete their own passkeys in their profile, each time confirmed with the password or an existing
  passkey. A password set in the same session does not count.
- Administrators with the permission can delete the passkeys of other users, without a confirmation. They cannot add any,
  and their own passkeys go through the profile.
- Deleting a passkey ends the sessions signed in with it on their next request.
- Every change is logged, appears in Sulu's activity log, and is mailed to the owner of the account.

## Requirements

Sulu 3 with PHP 8.4 or newer, Doctrine DBAL 4 and the skeleton's `admin` firewall with `json_login`. `security.yaml` needs no change.

The migration creates its table through Doctrine's schema, so it is not tied to MySQL: MariaDB and PostgreSQL get
their own SQL. The tests of this bundle run against MySQL only.

## Installation

```bash
composer require actualizer/sulu-passkey
```

Symfony Flex registers the bundle by itself. Without Flex, add it to `config/bundles.php` for all contexts:

```php
Actualizer\SuluPasskey\SuluPasskeyBundle::class => ['all' => true],
```

Set the public address of the admin. Its host becomes the WebAuthn relying party, so changing the domain later
invalidates all passkeys:

```dotenv
PASSKEY_ORIGIN=https://cms.example.com
```

Passkeys only work when the admin is opened on exactly this host. Any other host is refused, a subdomain of it
included.

Set a sender for the notification mails in `config/packages/sulu_passkey.yaml`. Do not skip this: without one, owners are
not told about changes to their passkeys, and for accounts without two-factor login that mail may be the only sign of a
stolen password (see [What this bundle cannot prevent](#what-this-bundle-cannot-prevent)).

```yaml
sulu_passkey:
    sender: '%env(SULU_ADMIN_EMAIL)%'
```

Then wire the project up and build. `sulu-passkey:install` adds the npm package and the import to `assets/admin` and the
routes to `config/routes`. It can be run again safely.

```bash
bin/adminconsole sulu-passkey:install
bin/adminconsole sulu:admin:update-build
bin/adminconsole doctrine:migrations:migrate
```

### Building the admin

`sulu:admin:update-build` compares `assets/admin` with the Sulu skeleton and asks about each file that differs. For
`package.json` its default is to overwrite your file with the skeleton's, which removes this bundle. So run it without
`--no-interaction` and answer:

- "Do you want to overwrite your local version of "package.json"?": `n`
- "Merge "package.json" together like above?": `y`
- "Do you want to overwrite your local version of "app.js"?": `n` (the default)

If `package.json` was overwritten, the build fails with `Can't resolve 'sulu-passkey-bundle'`. Run
`bin/adminconsole sulu-passkey:install` and `sulu:admin:update-build` again, this time with the answers above.

Do this after every Sulu update and every update of this bundle, and commit the build if your project keeps it in Git.

Behind a reverse proxy, configure Symfony's trusted proxies. The login rate limit counts per client IP, and without them
all clients share one limit, so one of them can block passkey logins for everyone.

On more than one server, challenges, locks and rate limits need a shared store: point the cache pools
`sulu_passkey.challenge_pool` and `cache.rate_limiter` and `framework.lock` at Redis or similar.

The rate limits below cover this bundle only. `/admin/login` is not limited by Sulu's default configuration, so turn on
Symfony's `login_throttling` for the `admin` firewall. This bundle was not tested together with it.

## Permissions

The role editor gets the entry "Passkeys" (`sulu.security.passkeys`) under Security. `view` shows a user's passkeys on
their permissions tab, `delete` removes them.

## Traces of a change

| Where | What | Limit |
| --- | --- | --- |
| Activity log | Who changed which user's passkeys | Readable with permission on users |
| Log, level `warning` | Actor, user, passkey | A `fingers_crossed` handler with `action_level: error`, the Symfony default for production, drops it |
| Mail to the owner | That a passkey was added or removed | Needs `sender`, goes to the address in the account at that moment, and is skipped if the user has none. A failed send is only logged |

## After an account takeover

Deleting a passkey ends only that passkey's sessions. A password session stays, so do all of this:

1. Lock the user. While locked, every session of the user is refused, password sessions too.
2. Delete the user's passkeys.
3. Reset the password and the two-factor setup. The new password is what ends any session that sent no request while
   the user was locked.
4. Unlock the user.

## What this bundle cannot prevent

The confirmation stops someone who has a session but not the password, for example at an unlocked computer. It does not
stop someone who already controls the account, and an admin account that is taken over can do everything anyway. What a
passkey adds is duration: it outlives a password reset until someone deletes it.

**A stolen password.** Two-factor login is off by default in Sulu. Without it, the password alone gives a full session,
and the real password passes the confirmation, so the attacker can add a passkey right away. Nothing changes for the
owner, whose password keeps working, so the mail is the only sign that reaches them directly.

**A stolen session.** Sulu's profile changes the password, the e-mail address and the two-factor setup without asking for
the current password. So whoever holds a session can set a new password, turn off the second factor, sign in again with
that password and then add a passkey. This bundle only refuses the shortcut, a password set in the session that uses it.
It cannot close the longer way without changing Sulu's profile.

The activity log and the mail make both visible, unless the e-mail address was changed first. After a stolen password or
session, resetting the password is not enough: check the user's passkeys and follow the steps above.

**A copied or software passkey.** User verification is a flag the authenticator reports. This bundle asks for no
attestation, so it cannot tell a phone with a fingerprint from a software key that just sets the flag.

**A copied key's counter.** A login whose signature counter did not go up is refused, and the passkey is marked with a
warning in both passkey lists. An authenticator that really reset its counter stays refused too: delete the passkey and
add it again. Synced passkeys usually stay at 0 and are never marked.

## Limits

- Login: 30 requests per minute per client, where a client is an IPv4 address or an IPv6 /64.
- Login and login options together: 600 requests per minute for all clients. Many addresses can reach this and block
  passkey logins for everyone for as long as they keep going. Password logins are not affected.
- Confirming with the password: 5 attempts per 15 minutes per user.
- A confirmation is for one change: adding one passkey, or deleting the passkey it was given for. It lasts 5 minutes
  and is used up when that change starts, also without session locking. An enrollment that was started has 2 minutes
  to finish.
- A challenge only redeems in the browser that asked for it. That browser gets the cookie
  `__Host-sulu_passkey_binding` for it, a random value that lasts until the browser is closed. Without HTTPS it is
  called `sulu_passkey_binding`.
- `cache:clear` drops the challenges and confirmations that are under way, so a login or enrollment in flight during
  a deploy has to start again.
- After changing your password, or coming in through a password reset mail, sign in again before the password counts as
  a confirmation. An existing passkey works right away.

## Development

npm keeps a copy of `assets/admin` in `node_modules`, so `npm install` alone does not pick up changed JavaScript of this
bundle. `sulu:admin:update-build` removes that copy first. In a manual build in `assets/admin`, delete
`node_modules/sulu-passkey-bundle`, then run `npm install` and `npm run build`.

The tests drive a real Sulu admin firewall in `tests/Application`. They need MySQL, see `DATABASE_URL` in
`phpunit.xml.dist`.

```bash
vendor/bin/phpunit
vendor/bin/phpstan analyse
```

## License

MIT
