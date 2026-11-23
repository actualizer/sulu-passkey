<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Unit;

use Actualizer\SuluPasskey\Entity\PasskeyCredential;
use Actualizer\SuluPasskey\Ceremony\AuthenticationCeremony;
use Actualizer\SuluPasskey\Ceremony\CeremonyFactory;
use Actualizer\SuluPasskey\Ceremony\RegistrationCeremony;
use Actualizer\SuluPasskey\Ceremony\WebauthnSerializer;
use Actualizer\SuluPasskey\Challenge\ChallengeStore;
use Actualizer\SuluPasskey\Credential\CredentialStore;
use Actualizer\SuluPasskey\Credential\UserHandleProvider;
use Actualizer\SuluPasskey\RelyingParty\RelyingParty;
use Actualizer\SuluPasskey\RelyingParty\UnsupportedHostException;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Sulu\Bundle\SecurityBundle\Entity\User;
use Sulu\Component\Security\Authentication\UserInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Lock\LockFactory;
use Symfony\Component\Lock\Store\InMemoryStore;
use Webauthn\Exception\AuthenticatorResponseVerificationException;

final class PasskeyCeremonyTest extends TestCase
{
    private const string HOST = 'cms.example.test';

    private const string ORIGIN = 'https://cms.example.test';

    private const string SESSION = 'session-a';

    private AuthenticationCeremony $authentication;

    private RegistrationCeremony $registration;

    private CredentialStore $credentials;

    private User $user;

    private ArrayAdapter $pool;

    protected function setUp(): void
    {
        $this->user = new User();
        $this->user->setUsername('redakteur');
        new \ReflectionProperty(User::class, 'id')->setValue($this->user, 7);

        $this->credentials = new class implements CredentialStore {
            /** @var array<string, PasskeyCredential> */
            private array $byCredentialId = [];

            public function findOneByCredentialId(string $credentialId): ?PasskeyCredential
            {
                return $this->byCredentialId[$credentialId] ?? null;
            }

            public function listOwned(UserInterface $user): array
            {
                return array_values($this->byCredentialId);
            }

            public function save(PasskeyCredential $credential): void
            {
                $this->byCredentialId[$credential->getCredentialId()] = $credential;
            }

            public function remove(PasskeyCredential $credential): void
            {
                unset($this->byCredentialId[$credential->getCredentialId()]);
            }

            public function findOfUser(string $id, int $userId): ?PasskeyCredential
            {
                foreach ($this->byCredentialId as $credential) {
                    if ($credential->getId() === $id && $credential->getUser()->getId() === $userId) {
                        return $credential;
                    }
                }

                return null;
            }

            public function exists(string $id): bool
            {
                foreach ($this->byCredentialId as $credential) {
                    if ($credential->getId() === $id) {
                        return true;
                    }
                }

                return false;
            }

            public function listOfUser(int $userId): array
            {
                return array_values($this->byCredentialId);
            }
        };

        $relyingParty = new RelyingParty(self::ORIGIN);
        $factory = new CeremonyFactory($relyingParty);
        $this->pool = new ArrayAdapter();
        $challenges = new ChallengeStore($this->pool, new MockClock(), new LockFactory(new InMemoryStore()));
        $serializer = new WebauthnSerializer();

        $this->registration = new RegistrationCeremony($factory, $challenges, $this->credentials, new UserHandleProvider('secret'), $relyingParty, $serializer);
        $this->authentication = new AuthenticationCeremony($factory, $challenges, $this->credentials, $relyingParty, $serializer, new NullLogger());
    }

    public function testAnEnrolledPasskeyLogsItsOwnerIn(): void
    {
        $authenticator = $this->enroll();
        $authenticator->counter = 5;

        $passkey = $this->login($authenticator);

        self::assertSame($this->user, $passkey->getUser());
        self::assertSame(5, $passkey->getSignCount());
    }

    public function testAChallengeOnlyRedeemsInTheSessionItWasIssuedTo(): void
    {
        $authenticator = $this->enroll();
        $created = $this->authentication->createOptions(self::HOST, self::SESSION);

        $this->expectExceptionMessage('Invalid or expired authentication challenge.');
        $this->authentication->verify($authenticator->sign($this->options($created['options'])), $created['challengeId'], self::HOST, 'session-of-a-victim');
    }

    public function testAChallengeWorksOnlyOnce(): void
    {
        $authenticator = $this->enroll();
        $created = $this->authentication->createOptions(self::HOST, self::SESSION);
        $assertion = $authenticator->sign($this->options($created['options']));
        $this->authentication->verify($assertion, $created['challengeId'], self::HOST, self::SESSION);

        $this->expectExceptionMessage('Invalid or expired authentication challenge.');
        $this->authentication->verify($assertion, $created['challengeId'], self::HOST, self::SESSION);
    }

    public function testASignatureOfAnotherKeyIsRefused(): void
    {
        $this->enroll();
        $created = $this->authentication->createOptions(self::HOST, self::SESSION);
        $stranger = new SoftwareAuthenticator(self::HOST, self::ORIGIN);

        $this->expectExceptionMessage('Unknown credential.');
        $this->authentication->verify($stranger->sign($this->options($created['options'])), $created['challengeId'], self::HOST, self::SESSION);
    }

    public function testAnAssertionForAnotherOriginIsRefused(): void
    {
        $authenticator = $this->enroll();
        $authenticator->origin = 'https://evil.test';
        $created = $this->authentication->createOptions(self::HOST, self::SESSION);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('origin');
        $this->authentication->verify($authenticator->sign($this->options($created['options'])), $created['challengeId'], self::HOST, self::SESSION);
    }

    public function testAFallingCounterRefusesTheLoginAndMarksThePasskey(): void
    {
        $authenticator = $this->enroll();
        $authenticator->counter = 5;
        $passkey = $this->login($authenticator);
        $authenticator->counter = 3;

        try {
            $this->login($authenticator);
            self::fail('The login must be refused.');
        } catch (\Throwable) {
            self::assertNotNull($passkey->getCloneWarningAt());
            self::assertSame(5, $passkey->getSignCount());
        }
    }

    public function testAnUnknownHostGetsNoRelyingParty(): void
    {
        $this->expectException(UnsupportedHostException::class);
        $this->authentication->createOptions('evil.test', self::SESSION);
    }

    public function testASubdomainOfTheConfiguredHostGetsNoneEither(): void
    {
        $this->expectException(UnsupportedHostException::class);

        new RelyingParty(self::ORIGIN)->id('www.cms.example.test');
    }

    public function testAnUnknownHostLeavesNoChallengeBehind(): void
    {
        try {
            $this->authentication->createOptions('evil.test', self::SESSION);
            self::fail('The host must be refused.');
        } catch (UnsupportedHostException) {
            self::assertSame([], $this->pool->getValues());
        }
    }

    private function enroll(): SoftwareAuthenticator
    {
        $authenticator = new SoftwareAuthenticator(self::HOST, self::ORIGIN);
        $created = $this->registration->createOptions($this->user, self::HOST, self::SESSION);
        $this->registration->verify(
            $this->user,
            $authenticator->register($this->options($created['options'])),
            $created['challengeId'],
            self::HOST,
            self::SESSION,
            'Testschlüssel',
        );

        return $authenticator;
    }

    private function login(SoftwareAuthenticator $authenticator): PasskeyCredential
    {
        $created = $this->authentication->createOptions(self::HOST, self::SESSION);

        return $this->authentication->verify($authenticator->sign($this->options($created['options'])), $created['challengeId'], self::HOST, self::SESSION);
    }

    /**
     * @return array{challenge: string, user: array{id: string}}
     */
    private function options(string $json): array
    {
        /** @var array{challenge: string, user: array{id: string}} */
        return json_decode($json, true, flags: \JSON_THROW_ON_ERROR);
    }
}
