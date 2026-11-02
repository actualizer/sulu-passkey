<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Http;

use Symfony\Component\HttpFoundation\Request;

/**
 * Only strings are taken from a body: anything else counts as missing.
 */
final class JsonPayload
{
    public static function string(Request $request, string $key): ?string
    {
        $payload = json_decode($request->getContent(), true);
        $value = \is_array($payload) ? ($payload[$key] ?? null) : null;

        return \is_string($value) ? $value : null;
    }
}
