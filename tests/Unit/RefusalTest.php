<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Unit;

use Actualizer\SuluPasskey\Http\Refusal;
use Doctrine\DBAL\Exception\InvalidArgumentException as DatabaseFailure;
use Doctrine\ORM\Exception\EntityManagerClosed;
use PHPUnit\Framework\TestCase;
use Webauthn\Exception\AuthenticatorResponseVerificationException;

final class RefusalTest extends TestCase
{
    public function testWhatTheClientSentWrongIsARefusal(): void
    {
        self::assertTrue(Refusal::covers(new \RuntimeException('Unknown credential.')));
        self::assertTrue(Refusal::covers(AuthenticatorResponseVerificationException::create('Invalid signature.')));
    }

    public function testWhatTheServerGotWrongIsNot(): void
    {
        self::assertFalse(Refusal::covers(new DatabaseFailure('gone away')));
        self::assertFalse(Refusal::covers(EntityManagerClosed::create()));
        self::assertFalse(Refusal::covers(new \TypeError('a bug')));
    }

    public function testTheLogGetsNoChainThatMayQuoteTheClient(): void
    {
        $context = Refusal::context(new \RuntimeException('Malformed credential response.', 0, new \RuntimeException('{"signature":"..."}')));

        self::assertSame(['type' => \RuntimeException::class, 'reason' => 'Malformed credential response.'], $context);
    }
}
