<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Http;

use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * The browser side needs the options as a JSON object and the id to send back with the signed result.
 */
final class ChallengeResponse
{
    /**
     * @param array{options: string, challengeId: string} $created
     */
    public static function of(array $created): JsonResponse
    {
        return new JsonResponse(['options' => json_decode($created['options'], true), 'challengeId' => $created['challengeId']]);
    }
}
