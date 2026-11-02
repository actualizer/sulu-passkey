<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Entity;

use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Sulu\Component\Security\Authentication\UserInterface;
use Symfony\Component\Uid\Uuid;

/**
 * A passkey of a Sulu admin user. The private key never leaves the authenticator, this only holds what is needed to
 * verify its signatures.
 */
#[ORM\Entity]
#[ORM\Table(name: 'sulu_passkey_credential')]
#[ORM\UniqueConstraint(name: 'uniq_sulu_passkey_credential_id', columns: ['credential_id'])]
class PasskeyCredential
{
    #[ORM\Id]
    #[ORM\Column(length: 36)]
    private string $id;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE, nullable: true)]
    private ?\DateTimeImmutable $lastUsedAt = null;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE, nullable: true)]
    private ?\DateTimeImmutable $cloneWarningAt = null;

    /**
     * @param list<string> $transports
     */
    public function __construct(
        #[ORM\ManyToOne(targetEntity: UserInterface::class)]
        #[ORM\JoinColumn(name: 'user_id', referencedColumnName: 'id', nullable: false, onDelete: 'CASCADE')]
        private UserInterface $user,
        #[ORM\Column(length: 255)]
        private string $rpId,
        #[ORM\Column(type: Types::BINARY, length: 1023)]
        private string $credentialId,
        #[ORM\Column(type: Types::BINARY, length: 1024)]
        private string $publicKey,
        #[ORM\Column(type: Types::BINARY, length: 64)]
        private string $userHandle,
        #[ORM\Column(options: ['unsigned' => true])]
        private int $signCount,
        #[ORM\Column(length: 36)]
        private string $aaguid,
        #[ORM\Column(type: Types::JSON)]
        private array $transports,
        #[ORM\Column(length: 120)]
        private string $name,
    ) {
        $this->id = Uuid::v7()->toRfc4122();
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getUser(): UserInterface
    {
        return $this->user;
    }

    public function getRpId(): string
    {
        return $this->rpId;
    }

    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function getUserHandle(): string
    {
        return $this->userHandle;
    }

    public function getSignCount(): int
    {
        return $this->signCount;
    }

    public function setSignCount(int $signCount): void
    {
        $this->signCount = $signCount;
    }

    public function getAaguid(): string
    {
        return $this->aaguid;
    }

    /**
     * @return list<string>
     */
    public function getTransports(): array
    {
        return $this->transports;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function getLastUsedAt(): ?\DateTimeImmutable
    {
        return $this->lastUsedAt;
    }

    public function setLastUsedAt(\DateTimeImmutable $lastUsedAt): void
    {
        $this->lastUsedAt = $lastUsedAt;
    }

    public function getCloneWarningAt(): ?\DateTimeImmutable
    {
        return $this->cloneWarningAt;
    }

    public function setCloneWarningAt(\DateTimeImmutable $cloneWarningAt): void
    {
        $this->cloneWarningAt = $cloneWarningAt;
    }
}
