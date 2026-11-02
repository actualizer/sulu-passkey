<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Controller;

use Actualizer\SuluPasskey\Entity\PasskeyCredential;

/**
 * What the admin shows of a passkey. Key material and the credential id stay on the server.
 */
final class CredentialView
{
    /**
     * @return array{id: string, name: string, createdAt: string, lastUsedAt: string|null, cloneWarningAt: string|null}
     */
    public static function of(PasskeyCredential $credential): array
    {
        return [
            'id' => $credential->getId(),
            'name' => $credential->getName(),
            'createdAt' => $credential->getCreatedAt()->format(\DATE_ATOM),
            'lastUsedAt' => $credential->getLastUsedAt()?->format(\DATE_ATOM),
            'cloneWarningAt' => $credential->getCloneWarningAt()?->format(\DATE_ATOM),
        ];
    }
}
