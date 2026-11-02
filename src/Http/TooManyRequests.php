<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Http;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\RateLimiter\RateLimit;

final class TooManyRequests
{
    public static function after(RateLimit $limit): JsonResponse
    {
        $seconds = max(1, $limit->getRetryAfter()->getTimestamp() - time());

        return new JsonResponse(['message' => 'Too many attempts.'], Response::HTTP_TOO_MANY_REQUESTS, ['Retry-After' => (string) $seconds]);
    }
}
