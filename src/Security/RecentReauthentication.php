<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Security;

use Actualizer\SuluPasskey\Challenge\ChallengePurpose;
use Actualizer\SuluPasskey\Challenge\ChallengeStore;
use Sulu\Component\Security\Authentication\UserInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * A new passkey is a permanent way into the account, so a session alone must not be enough to add one: a session can be
 * stolen or left open, and a passkey would outlive it and skip the e-mail code.
 *
 * The proof is for one change only, the one it was given for. It lives in the challenge store, which hands every entry
 * out once: the session only names it, so parallel requests of a session without locking cannot share it.
 */
final readonly class RecentReauthentication
{
    public const string ENROLLMENT = 'enroll';

    private const string KEY = 'sulu_passkey.reauthenticated';

    private const int LIFETIME_SECONDS = 300;

    public function __construct(private ChallengeStore $store)
    {
    }

    public static function deletionOf(string $credentialId): string
    {
        return 'delete:' . $credentialId;
    }

    public function record(Request $request, UserInterface $user, string $scope): void
    {
        $id = $this->store->issue($this->grant($user, $scope), ChallengePurpose::Confirmation, BrowserBinding::of($request), self::LIFETIME_SECONDS);

        $request->getSession()->set(self::KEY, $id);
    }

    /**
     * Uses the proof up, whether it fits or not.
     */
    public function redeem(Request $request, UserInterface $user, string $scope): bool
    {
        $id = $request->getSession()->remove(self::KEY);
        if (!\is_string($id)) {
            return false;
        }

        $grant = $this->store->consume($id, ChallengePurpose::Confirmation, BrowserBinding::of($request));

        return null !== $grant && hash_equals($this->grant($user, $scope), $grant);
    }

    private function grant(UserInterface $user, string $scope): string
    {
        return $user->getId() . ':' . $scope;
    }
}
