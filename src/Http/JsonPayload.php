<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Http;

use Symfony\Component\HttpFoundation\Request;

/**
 * Only strings are taken from a body: anything else counts as missing.
 */
final class JsonPayload
{
    private const string DECODED = '_sulu_passkey_payload';

    public static function string(Request $request, string $key): ?string
    {
        $payload = $request->attributes->get(self::DECODED);
        if (!\is_array($payload)) {
            // Only a body sent as JSON: a form on another site can post text that parses as JSON, but it cannot set
            // this content type.
            $payload = 'json' === $request->getContentTypeFormat() ? json_decode($request->getContent(), true) : null;
            $payload = \is_array($payload) ? $payload : [];
            $request->attributes->set(self::DECODED, $payload);
        }

        $value = $payload[$key] ?? null;

        return \is_string($value) ? $value : null;
    }
}
