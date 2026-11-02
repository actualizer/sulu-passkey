<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Security;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;

/**
 * A passkey with required user verification already proves possession and identity. scheb/2fa compares the exact token
 * class against its `security_tokens` list, so this subclass is what keeps the e-mail code from being asked on top.
 *
 * It remembers its passkey, so that PasskeySessionGuard can end the session once that passkey is deleted.
 */
final class PasskeyToken extends PostAuthenticationToken
{
    /**
     * @param string[] $roles
     */
    public function __construct(UserInterface $user, string $firewallName, array $roles, private string $credentialId)
    {
        parent::__construct($user, $firewallName, $roles);
    }

    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    public function __serialize(): array
    {
        return [$this->credentialId, parent::__serialize()];
    }

    /**
     * @param array{string, array<mixed>} $data
     */
    public function __unserialize(array $data): void
    {
        [$this->credentialId, $parentData] = $data;
        parent::__unserialize($parentData);
    }
}
