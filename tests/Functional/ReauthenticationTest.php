<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Functional;

use Actualizer\SuluPasskey\Tests\Unit\SoftwareAuthenticator;
use Sulu\Bundle\SecurityBundle\Entity\User;
use Symfony\Component\Clock\Test\ClockSensitiveTrait;

final class ReauthenticationTest extends FunctionalTestCase
{
    use ClockSensitiveTrait;

    public function testAFailedEnrollmentUsesUpTheConfirmation(): void
    {
        $this->passwordLogin($this->createUser());
        $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => self::PASSWORD]);
        $this->client->jsonRequest('POST', '/admin/passkey/register/options');
        /** @var array{challengeId: string} $created */
        $created = $this->json();

        $this->client->jsonRequest('POST', '/admin/passkey/register', ['challengeId' => $created['challengeId'], 'name' => 'x', 'credential' => '{}']);
        self::assertResponseStatusCodeSame(400);

        $this->client->jsonRequest('POST', '/admin/passkey/register/options');
        self::assertResponseStatusCodeSame(403);
    }

    public function testAStolenSessionCannotStartAnEnrollment(): void
    {
        $this->passwordLogin($this->createUser());

        $this->client->jsonRequest('POST', '/admin/passkey/register/options');

        self::assertResponseStatusCodeSame(403);
    }

    public function testTheRightPasswordOpensTheEnrollment(): void
    {
        $user = $this->createUser();
        $this->passwordLogin($user);

        $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => self::PASSWORD]);
        self::assertResponseStatusCodeSame(204);

        $this->registerNewPasskey();
        self::assertResponseIsSuccessful();
        self::assertCount(1, $this->passkeysOf($user));
    }

    public function testAWrongPasswordDoesNot(): void
    {
        $this->passwordLogin($this->createUser());

        $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => 'wrong']);
        self::assertResponseStatusCodeSame(403);

        $this->client->jsonRequest('POST', '/admin/passkey/register/options');
        self::assertResponseStatusCodeSame(403);
    }

    public function testOneReauthenticationEnrollsOnePasskey(): void
    {
        $user = $this->createUser();
        $this->passwordLogin($user);
        $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => self::PASSWORD]);
        $this->registerNewPasskey();

        $this->client->jsonRequest('POST', '/admin/passkey/register/options');

        self::assertResponseStatusCodeSame(403);
        self::assertCount(1, $this->passkeysOf($user));
    }

    public function testTheFinalStepChecksTheReauthenticationItself(): void
    {
        $user = $this->createUser();
        $this->passwordLogin($user);
        $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => self::PASSWORD]);
        $this->client->jsonRequest('POST', '/admin/passkey/register/options');
        /** @var array{options: array{challenge: string, user: array{id: string}}, challengeId: string} $created */
        $created = $this->json();

        self::mockTime('+6 minutes');
        $this->client->jsonRequest('POST', '/admin/passkey/register', [
            'challengeId' => $created['challengeId'],
            'name' => 'Laptop',
            'credential' => new SoftwareAuthenticator(self::HOST, self::ORIGIN)->register($created['options']),
        ]);

        self::assertResponseStatusCodeSame(403);
        self::assertCount(0, $this->passkeysOf($user));
    }

    public function testAReauthenticationExpires(): void
    {
        $this->passwordLogin($this->createUser());
        $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => self::PASSWORD]);

        self::mockTime('+6 minutes');
        $this->client->jsonRequest('POST', '/admin/passkey/register/options');

        self::assertResponseStatusCodeSame(403);
    }

    public function testPasswordGuessingIsLimitedPerUser(): void
    {
        $this->passwordLogin($this->createUser());
        for ($i = 0; $i < 5; ++$i) {
            $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => 'wrong']);
            self::assertResponseStatusCodeSame(403);
        }

        $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => self::PASSWORD]);

        self::assertResponseStatusCodeSame(429);
        $this->client->jsonRequest('POST', '/admin/passkey/register/options');
        self::assertResponseStatusCodeSame(403);
    }

    public function testAPasskeyOfTheUserAlsoReauthenticates(): void
    {
        $user = $this->createUser();
        $authenticator = $this->enroll($user);
        $this->passkeyLogin($authenticator);

        $this->passkeyReauthentication($authenticator);
        self::assertResponseStatusCodeSame(204);

        $this->registerNewPasskey();
        self::assertResponseIsSuccessful();
        self::assertCount(2, $this->passkeysOf($user));
    }

    public function testThePasskeyOfAnotherUserDoesNot(): void
    {
        $this->passkeyLogin($this->enroll($this->createUser()));

        $this->passkeyReauthentication($this->enroll($this->createUser()));

        self::assertResponseStatusCodeSame(403);
        $this->client->jsonRequest('POST', '/admin/passkey/register/options');
        self::assertResponseStatusCodeSame(403);
    }

    public function testALoginChallengeDoesNotReauthenticate(): void
    {
        $authenticator = $this->enroll($this->createUser());
        $this->passkeyLogin($authenticator);
        $created = $this->loginOptions();

        $this->client->jsonRequest('POST', '/admin/passkey/reauth', [
            'challengeId' => $created['challengeId'],
            'credential' => $authenticator->sign($created['options']),
        ]);

        self::assertResponseStatusCodeSame(403);
    }

    public function testAReauthenticationDoesNotCarryOverToTheNextUserOfTheBrowser(): void
    {
        $first = $this->createUser();
        $this->passwordLogin($first);
        $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => self::PASSWORD]);

        $this->passkeyLogin($this->enroll($this->createUser()));
        $this->client->jsonRequest('POST', '/admin/passkey/register/options');

        self::assertResponseStatusCodeSame(403);
    }

    public function testAPasswordSetInThisSessionDoesNotReauthenticate(): void
    {
        $user = $this->createUser();
        $this->passwordLogin($user);
        $this->changePasswordInProfile($user, 'chosen by whoever holds the session');

        $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => 'chosen by whoever holds the session']);

        self::assertResponseStatusCodeSame(403);
        $this->client->jsonRequest('POST', '/admin/passkey/register/options');
        self::assertResponseStatusCodeSame(403);
    }

    public function testTheOldPasswordDoesNotReauthenticateEither(): void
    {
        $user = $this->createUser();
        $this->passwordLogin($user);
        $this->changePasswordInProfile($user, 'something new');

        $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => self::PASSWORD]);

        self::assertResponseStatusCodeSame(403);
    }

    public function testASessionOfAPasskeyLoginCannotUseAPasswordItSetItself(): void
    {
        $user = $this->createUser();
        $this->passkeyLogin($this->enroll($user));
        $this->changePasswordInProfile($user, 'chosen by whoever holds the session');

        $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => 'chosen by whoever holds the session']);

        self::assertResponseStatusCodeSame(403);
    }

    public function testALoginWithTheNewPasswordWorksAgain(): void
    {
        $user = $this->createUser();
        $this->passwordLogin($user);
        $this->changePasswordInProfile($user, 'something new');
        $this->client->getCookieJar()->clear();

        $this->client->jsonRequest('POST', '/admin/login', ['username' => $user->getUsername(), 'password' => 'something new'], ['HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest']);
        self::assertResponseIsSuccessful();
        $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => 'something new']);

        self::assertResponseStatusCodeSame(204);
    }

    public function testAnEnrollmentIsRecordedAndTheOwnerIsTold(): void
    {
        $user = $this->createUser();
        $this->passwordLogin($user);
        $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => self::PASSWORD]);

        $this->registerNewPasskey();

        self::assertResponseIsSuccessful();
        self::assertEmailCount(1);
        $mail = self::getMailerMessage();
        self::assertNotNull($mail);
        self::assertEmailAddressContains($mail, 'To', (string) $user->getEmail());
        self::assertEmailTextBodyContains($mail, 'Laptop');
        self::assertTrue($this->logHandler()->hasWarningThatContains('Passkey added'));
        self::assertSame(1, $this->activities('passkey_added', $user));
    }

    public function testYourOwnPasskeyNeedsTheSameProofToBeDeleted(): void
    {
        $user = $this->createUser();
        $this->enroll($user);
        $id = $this->passkeysOf($user)[0]->getId();
        $this->passwordLogin($user);

        $this->client->request('DELETE', '/admin/passkey/credentials/' . $id);

        self::assertResponseStatusCodeSame(403);
        self::assertCount(1, $this->passkeysOf($user));
    }

    public function testADeletionWithProofIsRecordedAndTheOwnerIsTold(): void
    {
        $user = $this->createUser();
        $this->enroll($user);
        $id = $this->passkeysOf($user)[0]->getId();
        $this->passwordLogin($user);
        $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => self::PASSWORD]);

        $this->client->request('DELETE', '/admin/passkey/credentials/' . $id);

        self::assertResponseStatusCodeSame(204);
        self::assertCount(0, $this->passkeysOf($user));
        self::assertEmailCount(1);
        self::assertTrue($this->logHandler()->hasWarningThatContains('Passkey removed'));
        self::assertSame(1, $this->activities('passkey_removed', $user));
    }

    public function testTheEndpointsNeedALogin(): void
    {
        $this->client->jsonRequest('POST', '/admin/passkey/reauth', ['password' => 'x']);

        self::assertResponseStatusCodeSame(401);
    }

    private function passkeyReauthentication(SoftwareAuthenticator $authenticator): void
    {
        $this->client->jsonRequest('POST', '/admin/passkey/reauth/options');
        self::assertResponseIsSuccessful();
        /** @var array{options: array{challenge: string}, challengeId: string} $created */
        $created = $this->json();

        $this->client->jsonRequest('POST', '/admin/passkey/reauth', [
            'challengeId' => $created['challengeId'],
            'credential' => $authenticator->sign($created['options']),
        ]);
    }

    private function registerNewPasskey(): void
    {
        $this->client->jsonRequest('POST', '/admin/passkey/register/options');
        self::assertResponseIsSuccessful();
        /** @var array{options: array{challenge: string, user: array{id: string}}, challengeId: string} $created */
        $created = $this->json();

        $this->client->jsonRequest('POST', '/admin/passkey/register', [
            'challengeId' => $created['challengeId'],
            'name' => 'Laptop',
            'credential' => new SoftwareAuthenticator(self::HOST, self::ORIGIN)->register($created['options']),
        ]);
    }
}
