<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Credential;

use Actualizer\SuluPasskey\Entity\PasskeyCredential;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Sulu\Component\Security\Authentication\UserInterface;

final readonly class CredentialRepository implements CredentialStore
{
    public function __construct(private EntityManagerInterface $entityManager)
    {
    }

    public function findOneByCredentialId(string $credentialId): ?PasskeyCredential
    {
        return $this->repository()->findOneBy(['credentialId' => $credentialId]);
    }

    public function findOfUser(string $id, int $userId): ?PasskeyCredential
    {
        return $this->repository()->findOneBy(['id' => $id, 'user' => $userId]);
    }

    public function exists(string $id): bool
    {
        // A count, not find(): this runs on every request of a passkey session and needs no entity.
        return $this->repository()->count(['id' => $id]) > 0;
    }

    public function listOwned(UserInterface $user): array
    {
        return $this->listOfUser($user->getId());
    }

    public function listOfUser(int $userId): array
    {
        return $this->repository()->findBy(['user' => $userId], ['createdAt' => 'ASC']);
    }

    public function save(PasskeyCredential $credential): void
    {
        $this->entityManager->persist($credential);
        $this->entityManager->flush();
    }

    public function remove(PasskeyCredential $credential): void
    {
        $this->entityManager->remove($credential);
        $this->entityManager->flush();
    }

    /**
     * @return EntityRepository<PasskeyCredential>
     */
    private function repository(): EntityRepository
    {
        return $this->entityManager->getRepository(PasskeyCredential::class);
    }
}
