<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Unit;

use Actualizer\SuluPasskey\Migrations\Version20261101120000;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Platforms\MariaDBPlatform;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

require_once \dirname(__DIR__, 2) . '/migrations/Version20261101120000.php';

/**
 * BundleWiringTest runs the migration against the MySQL of the test application. The other two are built here.
 */
final class MigrationTest extends TestCase
{
    public function testItBuildsTheTableOnPostgreSql(): void
    {
        $sql = implode("\n", $this->migrated()->toSql(new PostgreSQLPlatform()));

        self::assertStringContainsString('CREATE TABLE sulu_passkey_credential', $sql);
        self::assertStringContainsString('credential_id BYTEA NOT NULL', $sql);
        self::assertStringContainsString('REFERENCES se_users (id) ON DELETE CASCADE', $sql);
    }

    public function testItBuildsTheTableOnMariaDb(): void
    {
        $sql = implode("\n", $this->migrated()->toSql(new MariaDBPlatform()));

        self::assertStringContainsString('CREATE TABLE sulu_passkey_credential', $sql);
        self::assertStringContainsString('credential_id VARBINARY(1023) NOT NULL', $sql);
    }

    private function migrated(): Schema
    {
        $schema = new Schema();
        new Version20261101120000($this->createStub(Connection::class), new NullLogger())->up($schema);

        return $schema;
    }
}
