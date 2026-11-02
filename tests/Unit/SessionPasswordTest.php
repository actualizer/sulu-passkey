<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Unit;

use Actualizer\SuluPasskey\Security\SessionPassword;
use PHPUnit\Framework\TestCase;
use Sulu\Bundle\SecurityBundle\Entity\User;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

final class SessionPasswordTest extends TestCase
{
    private Request $request;

    private User $user;

    protected function setUp(): void
    {
        $this->request = new Request();
        $this->request->setSession(new Session(new MockArraySessionStorage()));
        $this->user = new User();
        $this->user->setPassword('hash-1');
    }

    public function testASessionFromBeforeTheBundleWasInstalledIsNotTrusted(): void
    {
        self::assertFalse(new SessionPassword('secret')->isUnchanged($this->request, $this->user));
    }

    public function testThePasswordOfTheLoginIsTrusted(): void
    {
        $password = new SessionPassword('secret');
        $password->remember($this->request, $this->user);

        self::assertTrue($password->isUnchanged($this->request, $this->user));
    }

    public function testAPasswordChangedLaterIsNot(): void
    {
        $password = new SessionPassword('secret');
        $password->remember($this->request, $this->user);

        $this->user->setPassword('hash-2');

        self::assertFalse($password->isUnchanged($this->request, $this->user));
    }

    public function testTheSessionHoldsNoHash(): void
    {
        new SessionPassword('secret')->remember($this->request, $this->user);

        self::assertStringNotContainsString('hash-1', (string) json_encode($this->request->getSession()->all()));
    }
}
