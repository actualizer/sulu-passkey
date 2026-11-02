<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Migrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20261101120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Passkeys of Sulu admin users';
    }

    public function up(Schema $schema): void
    {
        $this->addSql(<<<'SQL'
            CREATE TABLE sulu_passkey_credential (
                id VARCHAR(36) NOT NULL,
                user_id INT NOT NULL,
                rp_id VARCHAR(255) NOT NULL,
                credential_id VARBINARY(1023) NOT NULL,
                public_key VARBINARY(1024) NOT NULL,
                user_handle VARBINARY(64) NOT NULL,
                sign_count INT UNSIGNED NOT NULL,
                aaguid VARCHAR(36) NOT NULL,
                transports JSON NOT NULL,
                name VARCHAR(120) NOT NULL,
                created_at DATETIME NOT NULL,
                last_used_at DATETIME DEFAULT NULL,
                clone_warning_at DATETIME DEFAULT NULL,
                INDEX IDX_B7C5A83FA76ED395 (user_id),
                UNIQUE INDEX uniq_sulu_passkey_credential_id (credential_id),
                PRIMARY KEY (id),
                CONSTRAINT FK_SULU_PASSKEY_USER FOREIGN KEY (user_id) REFERENCES se_users (id) ON DELETE CASCADE
            ) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB
            SQL);
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP TABLE sulu_passkey_credential');
    }
}
