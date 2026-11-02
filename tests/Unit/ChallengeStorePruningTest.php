<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Unit;

use Actualizer\SuluPasskey\Challenge\ChallengePurpose;
use Actualizer\SuluPasskey\Challenge\ChallengeStore;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\PruneableInterface;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Lock\LockFactory;
use Symfony\Component\Lock\Store\InMemoryStore;

final class ChallengeStorePruningTest extends TestCase
{
    public function testIssuingCleansUpSoAbandonedChallengesDoNotPileUp(): void
    {
        $pool = new class extends ArrayAdapter implements PruneableInterface {
            public int $pruned = 0;

            public function prune(): bool
            {
                ++$this->pruned;

                return true;
            }
        };

        new ChallengeStore($pool, new MockClock(), new LockFactory(new InMemoryStore()), pruneEvery: 1)
            ->issue('challenge', ChallengePurpose::Authentication);

        self::assertSame(1, $pool->pruned);
    }
}
