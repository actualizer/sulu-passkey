<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Security;

use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * Sulu's password reset signs the user in without this event, so a session that came through a reset mail has no
 * remembered password and needs a real login before a password counts as proof.
 */
final readonly class SessionPasswordListener
{
    /**
     * After Symfony's PasswordMigratingListener, which may rehash the password during the same event.
     */
    public const int PRIORITY = -1024;

    public function __construct(private SessionPassword $password)
    {
    }

    public function __invoke(LoginSuccessEvent $event): void
    {
        $this->password->remember($event->getRequest(), $event->getUser());
    }
}
