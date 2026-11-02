<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Credential;

use Actualizer\SuluPasskey\Entity\PasskeyCredential;
use Sulu\Component\Security\Authentication\UserInterface;

interface CredentialStore
{
    public const int MAX_NAME_LENGTH = 120;

    public function findOneByCredentialId(string $credentialId): ?PasskeyCredential;

    public function findOfUser(string $id, int $userId): ?PasskeyCredential;

    public function exists(string $id): bool;

    /**
     * @return list<PasskeyCredential>
     */
    public function listOwned(UserInterface $user): array;

    /**
     * @return list<PasskeyCredential>
     */
    public function listOfUser(int $userId): array;

    public function save(PasskeyCredential $credential): void;

    public function remove(PasskeyCredential $credential): void;
}
