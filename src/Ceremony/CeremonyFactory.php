<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Ceremony;

use Actualizer\SuluPasskey\RelyingParty\RelyingParty;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;

/**
 * Builds the webauthn-lib CeremonyStepManagers, pinning the allowed origins to the server-derived allowlist, never
 * the request Host header.
 */
final readonly class CeremonyFactory
{
    public function __construct(private RelyingParty $relyingParty)
    {
    }

    public function creation(): CeremonyStepManager
    {
        return $this->factory()->creationCeremony();
    }

    public function request(): CeremonyStepManager
    {
        return $this->factory()->requestCeremony();
    }

    private function factory(): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins($this->relyingParty->origins());
        // Same set as the serializer, or a parsed format still fails validation.
        $factory->setAttestationStatementSupportManager(AttestationSupport::manager());

        return $factory;
    }
}
