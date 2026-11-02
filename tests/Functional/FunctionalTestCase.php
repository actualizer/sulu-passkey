<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Functional;

use Actualizer\SuluPasskey\Ceremony\RegistrationCeremony;
use Actualizer\SuluPasskey\Entity\PasskeyCredential;
use Actualizer\SuluPasskey\Tests\Unit\SoftwareAuthenticator;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use Monolog\Handler\TestHandler;
use Psr\Cache\CacheItemPoolInterface;
use Sulu\Bundle\ContactBundle\Entity\Contact;
use Sulu\Bundle\SecurityBundle\Entity\Permission;
use Sulu\Bundle\SecurityBundle\Entity\Role;
use Sulu\Bundle\SecurityBundle\Entity\User;
use Sulu\Bundle\SecurityBundle\Entity\UserRole;
use Sulu\Bundle\SecurityBundle\Entity\UserTwoFactor;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * Drives the real firewall of tests/Application against a real database: nothing of the login path is mocked.
 */
abstract class FunctionalTestCase extends WebTestCase
{
    protected const string HOST = 'cms.example.test';

    protected const string ORIGIN = 'https://cms.example.test';

    protected const string PASSWORD = 'correct horse battery staple';

    protected KernelBrowser $client;

    private static bool $schemaCreated = false;

    protected function setUp(): void
    {
        $this->client = static::createClient([], ['HTTP_HOST' => self::HOST, 'HTTPS' => 'on']);
        // Rate limits count per IP, so one test's requests must not use up the next test's budget.
        $this->client->setServerParameter('REMOTE_ADDR', '10.' . random_int(0, 255) . '.' . random_int(0, 255) . '.' . random_int(1, 254));

        if (!self::$schemaCreated) {
            $entityManager = $this->entityManager();
            $schemaTool = new SchemaTool($entityManager);
            $metadata = $entityManager->getMetadataFactory()->getAllMetadata();
            $schemaTool->dropDatabase();
            $schemaTool->createSchema($metadata);
            // User ids start over with the schema, so the limits of the last run would hit the users of this one.
            $limits = static::getContainer()->get('cache.rate_limiter');
            \assert($limits instanceof CacheItemPoolInterface);
            $limits->clear();
            self::$schemaCreated = true;
        }
    }

    protected function entityManager(): EntityManagerInterface
    {
        $entityManager = static::getContainer()->get(EntityManagerInterface::class);
        \assert($entityManager instanceof EntityManagerInterface);

        return $entityManager;
    }

    /**
     * @param array<string, list<string>> $permissions security context => permission names of the user's role
     */
    protected function createUser(?string $twoFactorMethod = null, array $permissions = [], string $system = 'Sulu', bool $enabled = true, bool $locked = false): User
    {
        $entityManager = $this->entityManager();
        $username = 'user-' . bin2hex(random_bytes(6));

        $contact = new Contact();
        $contact->setFirstName('Test');
        $contact->setLastName($username);

        $role = new Role();
        $role->setName('role-' . $username);
        $role->setSystem($system);

        foreach ($permissions as $context => $names) {
            $mask = 0;
            foreach ($names as $name) {
                $mask |= ['view' => 64, 'add' => 32, 'edit' => 16, 'delete' => 8, 'archive' => 4, 'live' => 2, 'security' => 1][$name];
            }

            $permission = new Permission();
            $permission->setContext($context);
            $permission->setPermissions($mask);
            $permission->setRole($role);
            $role->addPermission($permission);
            $entityManager->persist($permission);
        }

        $user = new User();
        $user->setUsername($username);
        $user->setEmail($username . '@example.test');
        $user->setPassword((string) password_hash(self::PASSWORD, \PASSWORD_BCRYPT, ['cost' => 4]));
        $user->setSalt('');
        $user->setLocale('de');
        $user->setContact($contact);
        $user->setEnabled($enabled);
        $user->setLocked($locked);

        $userRole = new UserRole();
        $userRole->setUser($user);
        $userRole->setRole($role);
        $userRole->setLocale('["de"]');
        $user->addUserRole($userRole);

        $entityManager->persist($contact);
        $entityManager->persist($role);
        $entityManager->persist($user);
        $entityManager->persist($userRole);

        if (null !== $twoFactorMethod) {
            $twoFactor = new UserTwoFactor($user);
            $twoFactor->setMethod($twoFactorMethod);
            $user->setTwoFactor($twoFactor);
            $entityManager->persist($twoFactor);
        }

        $entityManager->flush();

        return $user;
    }

    protected function enroll(User $user): SoftwareAuthenticator
    {
        $ceremony = static::getContainer()->get(RegistrationCeremony::class);
        \assert($ceremony instanceof RegistrationCeremony);

        $authenticator = new SoftwareAuthenticator(self::HOST, self::ORIGIN);
        $created = $ceremony->createOptions($user, self::HOST, 'enrollment');
        /** @var array{challenge: string, user: array{id: string}} $options */
        $options = json_decode($created['options'], true, flags: \JSON_THROW_ON_ERROR);
        $ceremony->verify($user, $authenticator->register($options), $created['challengeId'], self::HOST, 'enrollment', 'Testschlüssel');

        return $authenticator;
    }

    /**
     * @return array{options: array{challenge: string, user: array{id: string}}, challengeId: string}
     */
    protected function loginOptions(): array
    {
        $this->client->jsonRequest('POST', '/admin/p/passkey/login/options');
        self::assertResponseIsSuccessful();

        /** @var array{options: array{challenge: string, user: array{id: string}}, challengeId: string} */
        return json_decode((string) $this->client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);
    }

    protected function passkeyLogin(SoftwareAuthenticator $authenticator): void
    {
        $created = $this->loginOptions();
        $this->client->jsonRequest('POST', '/admin/p/passkey/login', [
            'challengeId' => $created['challengeId'],
            'credential' => $authenticator->sign($created['options']),
        ]);
    }

    protected function passwordLogin(User $user): void
    {
        $this->client->jsonRequest('POST', '/admin/login', ['username' => $user->getUsername(), 'password' => self::PASSWORD], ['HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest']);
    }

    /**
     * @return array<mixed>
     */
    protected function json(): array
    {
        $data = json_decode((string) $this->client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        \assert(\is_array($data));

        return $data;
    }

    /**
     * @return list<PasskeyCredential> as the database has them now, not as the identity map of this test remembers them
     */
    protected function passkeysOf(User $user): array
    {
        $this->entityManager()->clear();

        return $this->entityManager()->getRepository(PasskeyCredential::class)->findBy(['user' => $user->getId()]);
    }

    protected function removeAllPasskeysOf(User $user): void
    {
        foreach ($this->passkeysOf($user) as $passkey) {
            $this->entityManager()->remove($passkey);
        }

        $this->entityManager()->flush();
    }

    protected function assertLoggedIn(): void
    {
        $this->client->request('GET', '/admin/passkey/credentials');
        self::assertResponseIsSuccessful();
    }

    protected function assertLoggedOut(): void
    {
        $this->client->request('GET', '/admin/passkey/credentials');
        self::assertResponseStatusCodeSame(401);
    }

    /**
     * What Sulu's own profile form sends. It does not ask for the current password.
     */
    protected function changePasswordInProfile(User $user, string $password): void
    {
        $this->client->jsonRequest('PUT', '/admin/api/profile', [
            'firstName' => 'Test',
            'lastName' => 'User',
            'username' => $user->getUsername(),
            'email' => $user->getEmail(),
            'locale' => 'de',
            'password' => $password,
        ]);
        self::assertResponseIsSuccessful();
    }

    protected function activities(string $type, User $user): int
    {
        $count = $this->entityManager()->getConnection()->fetchOne(
            'SELECT COUNT(*) FROM ac_activities WHERE type = ? AND resourceKey = ? AND resourceId = ?',
            [$type, 'users', (string) $user->getId()],
        );
        \assert(is_numeric($count));

        return (int) $count;
    }

    protected function logHandler(): TestHandler
    {
        $handler = static::getContainer()->get('monolog.handler.test');
        \assert($handler instanceof TestHandler);

        return $handler;
    }
}
