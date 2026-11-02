<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Security;

use Psr\Clock\ClockInterface;
use Sulu\Component\Security\Authentication\UserInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * A new passkey is a permanent way into the account, so a session alone must not be enough to add one: a session can be
 * stolen or left open, and a passkey would outlive it and skip the e-mail code. The proof lasts for one enrollment.
 */
final readonly class RecentReauthentication
{
    private const string KEY = 'sulu_passkey.reauthenticated';

    private const int LIFETIME_SECONDS = 300;

    public function __construct(private ClockInterface $clock)
    {
    }

    public function record(Request $request, UserInterface $user): void
    {
        $request->getSession()->set(self::KEY, ['user' => $user->getId(), 'at' => $this->clock->now()->getTimestamp()]);
    }

    public function holdsFor(Request $request, UserInterface $user): bool
    {
        $proof = $request->getSession()->get(self::KEY);

        return \is_array($proof)
            && $user->getId() === ($proof['user'] ?? null)
            && \is_int($proof['at'] ?? null)
            && $this->clock->now()->getTimestamp() - $proof['at'] <= self::LIFETIME_SECONDS;
    }

    public function forget(Request $request): void
    {
        $request->getSession()->remove(self::KEY);
    }
}
