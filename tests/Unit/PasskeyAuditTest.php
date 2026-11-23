<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Unit;

use Actualizer\SuluPasskey\Audit\PasskeyAudit;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Sulu\Bundle\ActivityBundle\Application\Collector\DomainEventCollectorInterface;
use Sulu\Bundle\SecurityBundle\Entity\User;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

final class PasskeyAuditTest extends TestCase
{
    public function testAFailingActivityLogNeitherLosesTheLogLineNorFailsTheChange(): void
    {
        $activities = $this->createStub(DomainEventCollectorInterface::class);
        $activities->method('dispatch')->willThrowException(new \RuntimeException('The entity manager is closed.'));

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with('Passkey removed');
        $logger->expects(self::once())->method('error');

        $user = new User();
        $user->setUsername('owner');

        new PasskeyAudit($activities, $logger, $this->createStub(MailerInterface::class), $this->createStub(TranslatorInterface::class), null)
            ->removed($user, $user, 'id', 'Laptop');
    }
}
