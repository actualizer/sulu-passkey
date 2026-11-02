<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Security;

use Sulu\Component\Security\Authentication\UserInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;

/**
 * Remembers which password a session began with. Sulu's profile sets a new password without asking for the current one,
 * so whoever holds a session could otherwise pick a password and then "confirm" with it. A password only counts as
 * proof while it is the one the session began with; a session that does not know is not trusted.
 *
 * The session holds a keyed hash of the password hash, never the hash itself.
 */
final readonly class SessionPassword
{
    private const string KEY = 'sulu_passkey.password';

    public function __construct(
        #[Autowire('%kernel.secret%')]
        private string $secret,
    ) {
    }

    public function remember(Request $request, object $user): void
    {
        $fingerprint = $this->fingerprint($user);
        if (null !== $fingerprint) {
            $request->getSession()->set(self::KEY, $fingerprint);
        }
    }

    public function isUnchanged(Request $request, UserInterface $user): bool
    {
        $remembered = $request->getSession()->get(self::KEY);
        $current = $this->fingerprint($user);

        return \is_string($remembered) && null !== $current && hash_equals($remembered, $current);
    }

    private function fingerprint(object $user): ?string
    {
        $hash = $user instanceof PasswordAuthenticatedUserInterface ? $user->getPassword() : null;

        return null === $hash ? null : hash_hmac('sha256', 'sulu-passkey-session-password:' . $hash, $this->secret);
    }
}
