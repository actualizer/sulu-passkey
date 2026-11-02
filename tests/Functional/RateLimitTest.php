<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Functional;

use Psr\Cache\CacheItemPoolInterface;

final class RateLimitTest extends FunctionalTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->clearLimits();
    }

    protected function tearDown(): void
    {
        // The ceiling is shared by all clients, so it must not reach into the next test.
        $this->clearLimits();
        parent::tearDown();
    }

    private function clearLimits(): void
    {
        $limits = static::getContainer()->get('cache.rate_limiter');
        \assert($limits instanceof CacheItemPoolInterface);
        $limits->clear();
    }

    public function testThePublicOptionsEndpointIsLimitedPerClient(): void
    {
        for ($i = 0; $i < 30; ++$i) {
            $this->client->jsonRequest('POST', '/admin/p/passkey/login/options');
            self::assertResponseIsSuccessful();
        }

        $this->client->jsonRequest('POST', '/admin/p/passkey/login/options');

        self::assertResponseStatusCodeSame(429);
        self::assertResponseHasHeader('Retry-After');
    }

    public function testAnotherClientIsNotAffected(): void
    {
        for ($i = 0; $i < 31; ++$i) {
            $this->client->jsonRequest('POST', '/admin/p/passkey/login/options');
        }

        $this->client->setServerParameter('REMOTE_ADDR', '10.200.' . random_int(0, 255) . '.' . random_int(1, 254));
        $this->client->jsonRequest('POST', '/admin/p/passkey/login/options');

        self::assertResponseIsSuccessful();
    }

    public function testAnIpv6ClientCannotEscapeByChangingItsHostBits(): void
    {
        for ($i = 0; $i < 30; ++$i) {
            $this->client->setServerParameter('REMOTE_ADDR', '2001:db8:1234:5678::' . dechex($i + 1));
            $this->client->jsonRequest('POST', '/admin/p/passkey/login/options');
            self::assertResponseIsSuccessful();
        }

        $this->client->setServerParameter('REMOTE_ADDR', '2001:db8:1234:5678::ffff');
        $this->client->jsonRequest('POST', '/admin/p/passkey/login/options');

        self::assertResponseStatusCodeSame(429);
    }

    public function testManyClientsTogetherHitACeiling(): void
    {
        for ($i = 0; $i < 600; ++$i) {
            $this->client->setServerParameter('REMOTE_ADDR', '10.77.' . ($i >> 8) . '.' . ($i & 255));
            $this->client->jsonRequest('POST', '/admin/p/passkey/login/options');
            self::assertResponseIsSuccessful();
        }

        $this->client->setServerParameter('REMOTE_ADDR', '10.78.0.1');
        $this->client->jsonRequest('POST', '/admin/p/passkey/login/options');

        self::assertResponseStatusCodeSame(429);
    }

    public function testAClientOverItsOwnLimitDoesNotUseUpTheCeiling(): void
    {
        for ($i = 0; $i < 620; ++$i) {
            $this->client->jsonRequest('POST', '/admin/p/passkey/login/options');
        }

        $this->client->setServerParameter('REMOTE_ADDR', '10.79.0.1');
        $this->client->jsonRequest('POST', '/admin/p/passkey/login/options');

        self::assertResponseIsSuccessful();
    }

    public function testTheCeilingCoversTheLoginToo(): void
    {
        for ($i = 0; $i < 600; ++$i) {
            $this->client->setServerParameter('REMOTE_ADDR', '10.80.' . ($i >> 8) . '.' . ($i & 255));
            $this->client->jsonRequest('POST', '/admin/p/passkey/login', ['credential' => '{}', 'challengeId' => 'x']);
        }

        $this->client->setServerParameter('REMOTE_ADDR', '10.81.0.1');
        $this->client->jsonRequest('POST', '/admin/p/passkey/login', ['credential' => '{}', 'challengeId' => 'x']);

        self::assertResponseStatusCodeSame(429);
    }

    public function testAClientLeavesNoLockFileBehind(): void
    {
        $address = '10.82.' . random_int(0, 255) . '.' . random_int(1, 254);
        $this->client->setServerParameter('REMOTE_ADDR', $address);

        $this->client->jsonRequest('POST', '/admin/p/passkey/login/options');

        self::assertResponseIsSuccessful();
        self::assertSame([], glob(\dirname(__DIR__) . '/Application/var/lock/*' . $address . '*'));
    }

    public function testAForeignHostIsARefusalNotAServerError(): void
    {
        $this->client->jsonRequest('POST', '/admin/p/passkey/login/options', server: ['HTTP_HOST' => 'evil.test']);

        self::assertResponseStatusCodeSame(400);
        self::assertStringNotContainsString('evil.test', (string) $this->client->getResponse()->getContent());
    }

    public function testTheLoginEndpointIsLimitedToo(): void
    {
        for ($i = 0; $i < 30; ++$i) {
            $this->client->jsonRequest('POST', '/admin/p/passkey/login', ['credential' => '{}', 'challengeId' => 'x']);
            self::assertResponseStatusCodeSame(401);
        }

        $this->client->jsonRequest('POST', '/admin/p/passkey/login', ['credential' => '{}', 'challengeId' => 'x']);

        self::assertResponseStatusCodeSame(429);
    }
}
