<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Ceremony;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;

/**
 * The attestation formats this bundle accepts. The same set must reach both the
 * serializer (parsing) and the creation ceremony (validation); a format known to
 * only one of them fails every registration that uses it.
 *
 * `packed` is here because some authenticators send a self-attestation despite
 * `attestation: none`. Trust chains are not checked: there is no metadata service.
 */
final class AttestationSupport
{
    private static ?AttestationStatementSupportManager $manager = null;

    public static function manager(): AttestationStatementSupportManager
    {
        return self::$manager ??= new AttestationStatementSupportManager([
            new NoneAttestationStatementSupport(),
            PackedAttestationStatementSupport::create(Manager::create()->add(ES256::create(), RS256::create())),
        ]);
    }
}
