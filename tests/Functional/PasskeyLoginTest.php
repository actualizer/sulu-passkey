<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Functional;

use Actualizer\SuluPasskey\Entity\PasskeyCredential;

final class PasskeyLoginTest extends FunctionalTestCase
{
    public function testAPasskeyLogsAUserWithEmailCodeInWithoutTheCode(): void
    {
        $user = $this->createUser(twoFactorMethod: 'email');

        $this->passkeyLogin($this->enroll($user));

        self::assertResponseIsSuccessful();
        $this->client->request('GET', '/admin/passkey/credentials');
        self::assertResponseIsSuccessful();
        self::assertEmailCount(0);
    }

    public function testAPasswordLoginOfTheSameKindOfUserStillAsksForTheCode(): void
    {
        $user = $this->createUser(twoFactorMethod: 'email');

        $this->passwordLogin($user);

        self::assertResponseIsSuccessful();
        /** @var array{completed: bool} $body */
        $body = json_decode((string) $this->client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertFalse($body['completed']);
        $this->client->request('GET', '/admin/passkey/credentials');
        self::assertResponseStatusCodeSame(401);
    }

    public function testTheAnswerIsTheOneSulusAdminExpectsFromALogin(): void
    {
        $user = $this->createUser();

        $this->passkeyLogin($this->enroll($user));

        self::assertResponseIsSuccessful();
        $body = $this->json();
        self::assertSame($user->getUsername(), $body['username'] ?? null);
        self::assertTrue($body['completed'] ?? null);
    }

    public function testALockedUserIsRefused(): void
    {
        $user = $this->createUser();
        $authenticator = $this->enroll($user);
        $user->setLocked(true);
        $this->entityManager()->flush();

        $this->passkeyLogin($authenticator);

        self::assertResponseStatusCodeSame(401);
        $this->assertNotLoggedIn();
    }

    public function testADisabledUserIsRefused(): void
    {
        $user = $this->createUser();
        $authenticator = $this->enroll($user);
        $user->setEnabled(false);
        $this->entityManager()->flush();

        $this->passkeyLogin($authenticator);

        self::assertResponseStatusCodeSame(401);
        $this->assertNotLoggedIn();
    }

    public function testAUserWithoutARoleInTheAdminSystemIsRefused(): void
    {
        $this->passkeyLogin($this->enroll($this->createUser(system: 'Website')));

        self::assertResponseStatusCodeSame(401);
        $this->assertNotLoggedIn();
    }

    public function testAnotherUsersEmailEqualToTheUsernameDoesNotBlockTheLogin(): void
    {
        $user = $this->createUser();
        $authenticator = $this->enroll($user);
        $other = $this->createUser();
        $other->setEmail($user->getUsername());
        $this->entityManager()->flush();

        $this->passkeyLogin($authenticator);

        self::assertResponseIsSuccessful();
        $this->assertLoggedIn();
        self::assertStringContainsString($user->getUsername(), $this->currentUserIdentifier());
    }

    public function testARefusedLoginDoesNotLookLikeARecentUse(): void
    {
        $user = $this->createUser();
        $authenticator = $this->enroll($user);
        $user->setLocked(true);
        $this->entityManager()->flush();

        $this->passkeyLogin($authenticator);

        $this->entityManager()->clear();
        $passkey = $this->entityManager()->getRepository(PasskeyCredential::class)->findOneBy(['user' => $user->getId()]);
        self::assertNotNull($passkey);
        self::assertNull($passkey->getLastUsedAt());
    }

    public function testASuccessfulLoginIsStamped(): void
    {
        $user = $this->createUser();

        $this->passkeyLogin($this->enroll($user));

        $passkey = $this->entityManager()->getRepository(PasskeyCredential::class)->findOneBy(['user' => $user->getId()]);
        self::assertNotNull($passkey);
        self::assertNotNull($passkey->getLastUsedAt());
    }

    public function testTheLoginChangesTheSessionId(): void
    {
        $authenticator = $this->enroll($this->createUser());
        $created = $this->loginOptions();
        $cookie = $this->client->getRequest()->getSession()->getName();
        $before = $this->client->getCookieJar()->get($cookie, '/admin')?->getValue();
        self::assertNotNull($before);

        $this->client->jsonRequest('POST', '/admin/p/passkey/login', [
            'challengeId' => $created['challengeId'],
            'credential' => $authenticator->sign($created['options']),
        ]);

        self::assertResponseIsSuccessful();
        self::assertNotSame($before, $this->client->getCookieJar()->get($cookie, '/admin')?->getValue());
    }

    public function testAChallengeOfAnotherBrowserIsRefused(): void
    {
        $authenticator = $this->enroll($this->createUser());
        $created = $this->loginOptions();
        $this->client->getCookieJar()->clear();

        $this->client->jsonRequest('POST', '/admin/p/passkey/login', [
            'challengeId' => $created['challengeId'],
            'credential' => $authenticator->sign($created['options']),
        ]);

        self::assertResponseStatusCodeSame(401);
    }

    public function testAMalformedLoginIsRefused(): void
    {
        $this->client->jsonRequest('POST', '/admin/p/passkey/login', ['credential' => ['no' => 'string']]);

        self::assertResponseStatusCodeSame(401);
    }

    private function currentUserIdentifier(): string
    {
        $this->client->request('GET', '/admin/api/profile');
        self::assertResponseIsSuccessful();
        $username = $this->json()['username'] ?? null;
        \assert(\is_string($username));

        return $username;
    }

    private function assertNotLoggedIn(): void
    {
        $this->client->request('GET', '/admin/passkey/credentials');
        self::assertResponseStatusCodeSame(401);
    }
}
