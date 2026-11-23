<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Migrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\DBAL\Types\Types;
use Doctrine\Migrations\AbstractMigration;

/**
 * Through the schema, not as SQL: Sulu runs on MySQL, MariaDB and PostgreSQL.
 */
final class Version20261101120000 extends AbstractMigration
{
    private const string TABLE = 'sulu_passkey_credential';

    public function getDescription(): string
    {
        return 'Passkeys of Sulu admin users';
    }

    public function up(Schema $schema): void
    {
        $table = $schema->createTable(self::TABLE);
        $table->addColumn('id', Types::STRING, ['length' => 36]);
        $table->addColumn('user_id', Types::INTEGER);
        $table->addColumn('rp_id', Types::STRING, ['length' => 255]);
        $table->addColumn('credential_id', Types::BINARY, ['length' => 1023]);
        $table->addColumn('public_key', Types::BINARY, ['length' => 1024]);
        $table->addColumn('user_handle', Types::BINARY, ['length' => 64]);
        $table->addColumn('sign_count', Types::INTEGER, ['unsigned' => true]);
        $table->addColumn('aaguid', Types::STRING, ['length' => 36]);
        $table->addColumn('transports', Types::JSON);
        $table->addColumn('name', Types::STRING, ['length' => 120]);
        $table->addColumn('created_at', Types::DATETIME_IMMUTABLE);
        $table->addColumn('last_used_at', Types::DATETIME_IMMUTABLE, ['notnull' => false]);
        $table->addColumn('clone_warning_at', Types::DATETIME_IMMUTABLE, ['notnull' => false]);
        $table->setPrimaryKey(['id']);
        $table->addUniqueIndex(['credential_id'], 'uniq_sulu_passkey_credential_id');
        $table->addIndex(['user_id'], 'IDX_B7C5A83FA76ED395');
        $table->addForeignKeyConstraint('se_users', ['user_id'], ['id'], ['onDelete' => 'CASCADE'], 'FK_SULU_PASSKEY_USER');
    }

    public function down(Schema $schema): void
    {
        $schema->dropTable(self::TABLE);
    }
}
