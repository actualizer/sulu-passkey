<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Challenge;

enum ChallengePurpose: string
{
    case Authentication = 'authentication';
    /** Not a WebAuthn challenge: the one-time proof of a reauthentication, kept in the same single-use store. */
    case Confirmation = 'confirmation';
    case Reauthentication = 'reauthentication';
    case Registration = 'registration';
}
