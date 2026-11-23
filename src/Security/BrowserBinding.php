<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Security;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

/**
 * The value a challenge is bound to: a random cookie of the browser that asked for it. Not the session, because the
 * login options are public and a session for every anonymous request would fill the session store.
 *
 * Over HTTPS the cookie carries the __Host- prefix, so no other host of the domain can set it for this one.
 */
final class BrowserBinding
{
    private const string NAME = 'sulu_passkey_binding';

    private const string ISSUED = '_sulu_passkey_binding';

    private const string PATTERN = '/^[0-9a-f]{64}\z/';

    public static function of(Request $request): string
    {
        $issued = $request->attributes->get(self::ISSUED);
        if (\is_string($issued)) {
            return $issued;
        }

        $binding = $request->cookies->get(self::name($request));
        if (\is_string($binding) && 1 === preg_match(self::PATTERN, $binding)) {
            return $binding;
        }

        $binding = bin2hex(random_bytes(32));
        $request->attributes->set(self::ISSUED, $binding);

        return $binding;
    }

    /**
     * Hands a binding made during this request to the browser.
     */
    public function __invoke(ResponseEvent $event): void
    {
        $request = $event->getRequest();
        $issued = $request->attributes->get(self::ISSUED);
        if (!\is_string($issued)) {
            return;
        }

        $event->getResponse()->headers->setCookie(
            Cookie::create(self::name($request), $issued, 0, '/', null, $request->isSecure(), true, false, Cookie::SAMESITE_STRICT),
        );
    }

    private static function name(Request $request): string
    {
        return ($request->isSecure() ? '__Host-' : '') . self::NAME;
    }
}
