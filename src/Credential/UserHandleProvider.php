<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Credential;

use Sulu\Component\Security\Authentication\UserInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * The WebAuthn user handle must stay the same between the two requests of an enrollment and must not reveal who the
 * user is. A keyed hash gives both without a table of its own; the stored credential keeps the value it was enrolled
 * with, so rotating the secret does not invalidate existing passkeys.
 */
final readonly class UserHandleProvider
{
    public function __construct(
        #[Autowire('%kernel.secret%')]
        private string $secret,
    ) {
    }

    public function handleFor(UserInterface $user): string
    {
        return hash_hmac('sha256', 'passkey-user-handle:' . $user->getId(), $this->secret, true);
    }
}
