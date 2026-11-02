<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Functional;

use Actualizer\SuluPasskey\Admin\PasskeyAdmin;
use Actualizer\SuluPasskey\Entity\PasskeyCredential;
use Actualizer\SuluPasskey\Tests\Application\Kernel;
use Doctrine\ORM\Tools\SchemaTool;
use Sulu\Bundle\AdminBundle\Admin\AdminPool;
use Sulu\Component\HttpKernel\SuluKernel;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

final class BundleWiringTest extends FunctionalTestCase
{
    public function testTheProfileFormGetsThePasskeysField(): void
    {
        $this->passkeyLogin($this->enroll($this->createUser()));

        $this->client->request('GET', '/admin/metadata/form/profile_details');

        self::assertResponseIsSuccessful();
        self::assertArrayHasKey('passkeys', $this->formFields());
    }

    public function testThePasskeysComeAfterSulusOwnFieldsInTheProfile(): void
    {
        $this->passkeyLogin($this->enroll($this->createUser()));

        $this->client->request('GET', '/admin/metadata/form/profile_details');

        $fields = $this->formFields();
        self::assertArrayHasKey('firstName', $fields);
        self::assertSame('passkeys', array_key_last($fields));
    }

    public function testThePasskeysComeAfterSulusOwnFieldsInTheUserForm(): void
    {
        $this->passkeyLogin($this->enroll($this->createUser(permissions: ['sulu.security.passkeys' => ['view']])));

        $this->client->request('GET', '/admin/metadata/form/user_details');

        $fields = $this->formFields();
        self::assertArrayHasKey('username', $fields);
        self::assertSame('user_passkeys', array_key_last($fields));
    }

    public function testTheUserFormGetsTheFieldWithThePermission(): void
    {
        $this->passkeyLogin($this->enroll($this->createUser(permissions: ['sulu.security.passkeys' => ['view']])));

        $this->client->request('GET', '/admin/metadata/form/user_details');

        self::assertResponseIsSuccessful();
        self::assertArrayHasKey('user_passkeys', $this->formFields());
    }

    public function testTheUserFormHidesTheFieldWithoutIt(): void
    {
        $this->passkeyLogin($this->enroll($this->createUser()));

        $this->client->request('GET', '/admin/metadata/form/user_details');

        self::assertResponseIsSuccessful();
        self::assertArrayNotHasKey('user_passkeys', $this->formFields());
    }

    public function testTheSecurityContextCanBeGrantedInTheRoleEditor(): void
    {
        $pool = static::getContainer()->get('sulu_admin.admin_pool');
        \assert($pool instanceof AdminPool);

        $admins = array_filter($pool->getAdmins(), static fn (object $admin): bool => $admin instanceof PasskeyAdmin);

        self::assertCount(1, $admins);
        self::assertSame(['view', 'delete'], array_values($admins)[0]->getSecurityContexts()['Sulu']['Security']['sulu.security.passkeys']);
    }

    public function testTheTranslationsReachTheAdmin(): void
    {
        $this->client->request('GET', '/admin/translations?locale=de');

        self::assertResponseIsSuccessful();
        self::assertSame('Passkey hinzufügen', $this->json()['sulu_passkey.add'] ?? null);
    }

    public function testTheMigrationCreatesTheMappedTable(): void
    {
        $entityManager = $this->entityManager();
        $connection = $entityManager->getConnection();
        $connection->executeStatement('DROP TABLE sulu_passkey_credential');

        $command = new Application(self::$kernel ?? throw new \LogicException())->find('doctrine:migrations:migrate');
        $tester = new CommandTester($command);
        $tester->execute(['--no-interaction' => true, 'version' => 'latest'], ['interactive' => false]);
        self::assertSame(0, $tester->getStatusCode(), $tester->getDisplay());

        $updates = new SchemaTool($entityManager)->getUpdateSchemaSql([$entityManager->getClassMetadata(PasskeyCredential::class)]);
        self::assertSame([], array_values(array_filter($updates, static fn (string $sql): bool => str_contains($sql, 'sulu_passkey_credential'))));
    }

    public function testTheWebsiteContextBootsWithoutTheAdminSide(): void
    {
        $kernel = new Kernel('test', true, SuluKernel::CONTEXT_WEBSITE);
        $kernel->boot();

        self::assertFalse($kernel->getContainer()->has('Actualizer\SuluPasskey\Controller\LoginController'));
        $kernel->shutdown();
    }

    /**
     * @return array<mixed>
     */
    private function formFields(): array
    {
        $form = $this->json()['form'] ?? null;
        \assert(\is_array($form));

        return $form;
    }
}
