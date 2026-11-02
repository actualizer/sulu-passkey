<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Admin;

use Sulu\Bundle\AdminBundle\Admin\Admin;
use Sulu\Component\Security\Authorization\PermissionTypes;

/**
 * Adds the permission for managing other users' passkeys to Sulu's role editor.
 */
final class PasskeyAdmin extends Admin
{
    public const string SECURITY_CONTEXT = 'sulu.security.passkeys';

    public function getSecurityContexts(): array
    {
        return [
            self::SULU_ADMIN_SECURITY_SYSTEM => [
                'Security' => [
                    self::SECURITY_CONTEXT => [PermissionTypes::VIEW, PermissionTypes::DELETE],
                ],
            ],
        ];
    }
}
