<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Audit;

use Sulu\Bundle\ActivityBundle\Domain\Event\DomainEvent;
use Sulu\Bundle\SecurityBundle\Admin\SecurityAdmin;
use Sulu\Component\Security\Authentication\UserInterface;

/**
 * An entry in Sulu's activity log, on the user whose account changed.
 */
final class PasskeyChangedEvent extends DomainEvent
{
    public function __construct(
        private readonly string $type,
        private readonly UserInterface $owner,
        private readonly string $passkeyId,
        private readonly string $passkeyName,
    ) {
        parent::__construct();
    }

    public function getEventType(): string
    {
        return $this->type;
    }

    public function getEventPayload(): array
    {
        return ['passkey' => $this->passkeyId, 'name' => $this->passkeyName];
    }

    public function getResourceKey(): string
    {
        return UserInterface::RESOURCE_KEY;
    }

    public function getResourceId(): string
    {
        return (string) $this->owner->getId();
    }

    public function getResourceTitle(): string
    {
        return $this->owner->getUserIdentifier();
    }

    public function getResourceSecurityContext(): string
    {
        return SecurityAdmin::USER_SECURITY_CONTEXT;
    }
}
