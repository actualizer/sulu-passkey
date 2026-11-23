<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Security;

use Symfony\Component\Security\Http\Event\AuthenticationTokenCreatedEvent;

/**
 * Security::login() has to go through an authenticator of the firewall, and json_login creates a token on scheb's
 * `security_tokens` list, which would ask for the e-mail code. This swaps it for a PasskeyToken before scheb looks at it.
 *
 * Only passports with the attribute are touched. LoginController is the only code that sets it, after verifying an
 * assertion; a password login never carries it, so its second factor stays.
 */
final class PasskeyTokenListener
{
    public const string CREDENTIAL_ATTRIBUTE = 'sulu_passkey.credential';

    public const string FIREWALL = 'admin';

    /**
     * Has to run before scheb's AuthenticationTokenListener, which has priority 0.
     */
    public const int PRIORITY = 1;

    public function __invoke(AuthenticationTokenCreatedEvent $event): void
    {
        $passport = $event->getPassport();
        $credentialId = $passport->getAttribute(self::CREDENTIAL_ATTRIBUTE);
        if (!\is_string($credentialId)) {
            return;
        }

        $user = $passport->getUser();
        $event->setAuthenticatedToken(new PasskeyToken($user, self::FIREWALL, $user->getRoles(), $credentialId));
    }
}
