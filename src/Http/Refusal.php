<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Http;

use Doctrine\DBAL\Exception as DbalException;
use Doctrine\ORM\Exception\ManagerException;
use Doctrine\ORM\Exception\ORMException;

/**
 * Tells what a client sent wrong from what this server got wrong. Validator, lookup and counter failures share no base
 * class, and every one of them is a refusal. A database failure or a PHP error is not: answered as a refusal, it would
 * look like a wrong passkey and never reach an error log.
 */
final class Refusal
{
    public static function covers(\Throwable $exception): bool
    {
        return $exception instanceof \Exception
            && !$exception instanceof DbalException
            && !$exception instanceof ORMException
            && !$exception instanceof ManagerException;
    }

    /**
     * Class and message only. The chain behind it may quote what the client sent.
     *
     * @return array{type: class-string, reason: string}
     */
    public static function context(\Throwable $exception): array
    {
        return ['type' => $exception::class, 'reason' => $exception->getMessage()];
    }
}
