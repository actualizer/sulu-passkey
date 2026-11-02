<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Security;

use Symfony\Component\HttpFoundation\Request;

/**
 * The value a challenge is bound to. A random session value instead of the session id: Symfony only sends the cookie
 * of a non-empty session, and the id changes on login.
 */
final class SessionBinding
{
    private const string KEY = 'passkey.binding';

    public static function of(Request $request): string
    {
        $session = $request->getSession();
        $binding = $session->get(self::KEY);
        if (!\is_string($binding)) {
            $binding = bin2hex(random_bytes(32));
            $session->set(self::KEY, $binding);
        }

        return $binding;
    }
}
