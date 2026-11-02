<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Functional;

use Actualizer\SuluPasskey\Entity\PasskeyCredential;

final class SessionGuardTest extends FunctionalTestCase
{
    public function testDeletingThePasskeyEndsItsSessionOnTheNextRequest(): void
    {
        $user = $this->createUser();
        $this->passkeyLogin($this->enroll($user));
        $this->assertLoggedIn();

        $this->removeAllPasskeysOf($user);

        $this->assertLoggedOut();
    }

    public function testDeletingThePasskeyOfYourOwnSessionSucceedsAndThenEndsTheSession(): void
    {
        $user = $this->createUser();
        $authenticator = $this->enroll($user);
        $id = $this->passkeysOf($user)[0]->getId();
        $this->passkeyLogin($authenticator);

        $this->client->jsonRequest('POST', '/admin/passkey/reauth/options');
        /** @var array{options: array{challenge: string}, challengeId: string} $created */
        $created = $this->json();
        $this->client->jsonRequest('POST', '/admin/passkey/reauth', [
            'challengeId' => $created['challengeId'],
            'credential' => $authenticator->sign($created['options']),
        ]);
        $this->client->request('DELETE', '/admin/passkey/credentials/' . $id);

        self::assertResponseStatusCodeSame(204);
        self::assertCount(0, $this->passkeysOf($user));
        $this->assertLoggedOut();
    }

    public function testTheSessionStaysEndedAfterwards(): void
    {
        $user = $this->createUser();
        $this->passkeyLogin($this->enroll($user));
        $this->removeAllPasskeysOf($user);
        $this->assertLoggedOut();

        $this->assertLoggedOut();
    }

    public function testDeletingAnotherPasskeyOfTheUserKeepsTheSession(): void
    {
        $user = $this->createUser();
        $first = $this->enroll($user);
        $this->enroll($user);
        $this->passkeyLogin($first);

        // Only the passkey of this login carries a stamp, so this is the other one.
        $other = array_values(array_filter($this->passkeysOf($user), static fn (PasskeyCredential $passkey): bool => null === $passkey->getLastUsedAt()))[0];
        $this->entityManager()->remove($other);
        $this->entityManager()->flush();

        $this->assertLoggedIn();
    }

    public function testAPasswordSessionDoesNotDependOnPasskeys(): void
    {
        $user = $this->createUser();
        $this->enroll($user);
        $this->passwordLogin($user);

        $this->removeAllPasskeysOf($user);

        $this->assertLoggedIn();
    }

    public function testADocumentRequestIsSentBackToTheAdmin(): void
    {
        $user = $this->createUser();
        $this->passkeyLogin($this->enroll($user));
        $this->removeAllPasskeysOf($user);

        $this->client->request('GET', '/admin/passkey/credentials', server: ['HTTP_ACCEPT' => 'text/html']);

        self::assertResponseRedirects('/admin');
    }

    public function testLockingAUserEndsAPasswordSession(): void
    {
        $user = $this->createUser();
        $this->passwordLogin($user);
        $this->assertLoggedIn();

        $user = $this->entityManager()->find($user::class, $user->getId());
        self::assertNotNull($user);
        $user->setLocked(true);
        $this->entityManager()->flush();

        $this->assertLoggedOut();
    }
}
