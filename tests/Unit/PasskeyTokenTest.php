<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Unit;

use Actualizer\SuluPasskey\Security\PasskeyToken;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\User\InMemoryUser;

final class PasskeyTokenTest extends TestCase
{
    public function testTheCredentialSurvivesTheSession(): void
    {
        $token = new PasskeyToken(new InMemoryUser('redakteur', null, ['ROLE_USER']), 'admin', ['ROLE_USER'], 'credential-1');

        $restored = unserialize(serialize($token));

        self::assertInstanceOf(PasskeyToken::class, $restored);
        self::assertSame('credential-1', $restored->getCredentialId());
        self::assertSame('admin', $restored->getFirewallName());
        self::assertSame('redakteur', $restored->getUserIdentifier());
        self::assertSame(['ROLE_USER'], $restored->getRoleNames());
    }
}
