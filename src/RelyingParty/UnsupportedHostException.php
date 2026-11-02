<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\RelyingParty;

use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

/**
 * A 400: a request with a foreign Host header is the client's mistake. The host stays out of the message, it is
 * attacker-controlled and ends up in the log.
 */
final class UnsupportedHostException extends BadRequestHttpException
{
    public function __construct()
    {
        parent::__construct('No passkey relying party for this host.');
    }
}
