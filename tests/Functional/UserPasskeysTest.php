<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Functional;

use Monolog\Level;

final class UserPasskeysTest extends FunctionalTestCase
{
    private const string CONTEXT = 'sulu.security.passkeys';

    public function testAUserWithoutThePermissionSeesNothing(): void
    {
        $target = $this->createUser();
        $this->enroll($target);
        $this->passkeyLogin($this->enroll($this->createUser()));

        $this->client->request('GET', '/admin/passkey/users/' . $target->getId() . '/credentials');

        self::assertResponseStatusCodeSame(403);
    }

    public function testViewAloneListsButDoesNotDelete(): void
    {
        $target = $this->createUser();
        $this->enroll($target);
        $id = $this->passkeysOf($target)[0]->getId();
        $this->passkeyLogin($this->enroll($this->createUser(permissions: [self::CONTEXT => ['view']])));

        $this->client->request('GET', '/admin/passkey/users/' . $target->getId() . '/credentials');
        self::assertResponseIsSuccessful();
        self::assertStringContainsString($id, (string) $this->client->getResponse()->getContent());

        $this->client->request('DELETE', '/admin/passkey/users/' . $target->getId() . '/credentials/' . $id);
        self::assertResponseStatusCodeSame(403);
        self::assertCount(1, $this->passkeysOf($target));
    }

    public function testTheDeletePermissionRemovesAPasskeyOfAnotherUser(): void
    {
        $target = $this->createUser();
        $this->enroll($target);
        $id = $this->passkeysOf($target)[0]->getId();
        $this->passkeyLogin($this->enroll($this->createUser(permissions: [self::CONTEXT => ['view', 'delete']])));

        $this->client->request('DELETE', '/admin/passkey/users/' . $target->getId() . '/credentials/' . $id);

        self::assertResponseStatusCodeSame(204);
        self::assertCount(0, $this->passkeysOf($target));
    }

    public function testAPasskeyOfSomeoneElseIsNotFoundUnderTheWrongUser(): void
    {
        $target = $this->createUser();
        $other = $this->createUser();
        $this->enroll($target);
        $id = $this->passkeysOf($target)[0]->getId();
        $this->passkeyLogin($this->enroll($this->createUser(permissions: [self::CONTEXT => ['view', 'delete']])));

        $this->client->request('DELETE', '/admin/passkey/users/' . $other->getId() . '/credentials/' . $id);

        self::assertResponseStatusCodeSame(404);
        self::assertCount(1, $this->passkeysOf($target));
    }

    public function testTheDeletionIsLoggedWithAdminUserAndPasskey(): void
    {
        $target = $this->createUser();
        $this->enroll($target);
        $id = $this->passkeysOf($target)[0]->getId();
        $admin = $this->createUser(permissions: [self::CONTEXT => ['delete']]);
        $this->passkeyLogin($this->enroll($admin));

        $this->client->request('DELETE', '/admin/passkey/users/' . $target->getId() . '/credentials/' . $id);

        self::assertTrue($this->logHandler()->hasRecordThatPasses(static fn ($record): bool => Level::Warning === $record->level
            && $admin->getUserIdentifier() === ($record->context['actor'] ?? null)
            && $target->getUserIdentifier() === ($record->context['user'] ?? null)
            && $id === ($record->context['passkey'] ?? null), Level::Warning));
        self::assertSame(1, $this->activities('passkey_removed', $target));
    }

    public function testTheOwnerIsToldWhenAnAdministratorTakesAPasskey(): void
    {
        $target = $this->createUser();
        $this->enroll($target);
        $id = $this->passkeysOf($target)[0]->getId();
        $this->passkeyLogin($this->enroll($this->createUser(permissions: [self::CONTEXT => ['delete']])));

        $this->client->request('DELETE', '/admin/passkey/users/' . $target->getId() . '/credentials/' . $id);

        self::assertEmailCount(1);
        $mail = self::getMailerMessage();
        self::assertNotNull($mail);
        self::assertEmailAddressContains($mail, 'To', (string) $target->getEmail());
    }

    public function testTheSessionOfTheDeletedPasskeyEndsOnItsNextClick(): void
    {
        $target = $this->createUser();
        $authenticator = $this->enroll($target);
        $id = $this->passkeysOf($target)[0]->getId();
        $this->passkeyLogin($authenticator);
        $targetCookies = $this->client->getCookieJar()->all();

        $this->client->getCookieJar()->clear();
        $this->passkeyLogin($this->enroll($this->createUser(permissions: [self::CONTEXT => ['delete']])));
        $this->client->request('DELETE', '/admin/passkey/users/' . $target->getId() . '/credentials/' . $id);
        self::assertResponseStatusCodeSame(204);

        $this->client->getCookieJar()->clear();
        foreach ($targetCookies as $cookie) {
            $this->client->getCookieJar()->set($cookie);
        }

        $this->assertLoggedOut();
    }

    public function testYourOwnPasskeysCannotBeDeletedWithoutConfirmationHere(): void
    {
        $admin = $this->createUser(permissions: [self::CONTEXT => ['view', 'delete']]);
        $this->enroll($admin);
        $id = $this->passkeysOf($admin)[0]->getId();
        $this->client->getCookieJar()->clear();
        $this->passwordLogin($admin);

        $this->client->request('DELETE', '/admin/passkey/users/' . $admin->getId() . '/credentials/' . $id);

        self::assertResponseStatusCodeSame(403);
        self::assertCount(1, $this->passkeysOf($admin));
    }

    public function testACloneWarningIsShownToTheAdministrator(): void
    {
        $target = $this->createUser();
        $this->enroll($target);
        $passkey = $this->passkeysOf($target)[0];
        $passkey->setCloneWarningAt(new \DateTimeImmutable());
        $this->entityManager()->flush();
        $this->passkeyLogin($this->enroll($this->createUser(permissions: [self::CONTEXT => ['view']])));

        $this->client->request('GET', '/admin/passkey/users/' . $target->getId() . '/credentials');

        /** @var array{credentials: list<array{cloneWarningAt: string|null}>} $body */
        $body = $this->json();
        self::assertNotNull($body['credentials'][0]['cloneWarningAt']);
    }

    public function testNothingNeedsALoginToBeRefused(): void
    {
        $this->client->request('GET', '/admin/passkey/users/1/credentials');

        self::assertResponseStatusCodeSame(401);
    }
}
