<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Challenge;

enum ChallengePurpose: string
{
    case Authentication = 'authentication';
    case Reauthentication = 'reauthentication';
    case Registration = 'registration';
}
