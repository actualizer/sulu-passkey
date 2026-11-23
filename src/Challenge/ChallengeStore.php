<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Challenge;

use Psr\Cache\CacheItemPoolInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\Cache\PruneableInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Lock\LockFactory;

/**
 * Cache-backed, single-use, TTL-expiring store for WebAuthn challenges.
 *
 * Backed by our own pool (`sulu_passkey.challenge_pool`), so clearing the pool `cache.app` cannot drop a challenge
 * between the two requests of a passkey flow (issue, then redeem).
 */
final class ChallengeStore
{
    private const string KEY_PREFIX = 'sulu_passkey_challenge.';

    private const string LOCK_PREFIX = 'sulu_passkey_challenge_consume.';

    /**
     * Challenge ids are always bin2hex(random_bytes(16)). `\z`, not `$`: `$` also matches before a trailing newline.
     */
    private const string ID_PATTERN = '/^[0-9a-f]{32}\z/';

    public function __construct(
        #[Autowire(service: 'sulu_passkey.challenge_pool')]
        private readonly CacheItemPoolInterface $cache,
        private readonly ClockInterface $clock,
        private readonly LockFactory $lockFactory,
        /**
         * A challenge nobody redeems stays on disk: the filesystem pool only drops expired files when pruned, and the
         * login options are public. One issue in this many cleans up.
         */
        private readonly int $pruneEvery = 100,
    ) {
    }

    /**
     * `$binding` ties the challenge to the browser it was handed out to. Only its hash is stored.
     */
    public function issue(string $rawChallenge, ChallengePurpose $purpose, string $binding, int $ttlSeconds = 120): string
    {
        $id = bin2hex(random_bytes(16));
        $item = $this->cache->getItem(self::KEY_PREFIX . $id);
        $item->set([
            'challenge' => base64_encode($rawChallenge),
            'purpose' => $purpose->value,
            'binding' => hash('sha256', $binding),
            'expires' => $this->clock->now()->getTimestamp() + $ttlSeconds,
        ]);
        $item->expiresAfter($ttlSeconds + 5); // backstop; primary check below
        $this->cache->save($item);

        if ($this->cache instanceof PruneableInterface && 1 === random_int(1, $this->pruneEvery)) {
            $this->cache->prune();
        }

        return $id;
    }

    public function consume(string $challengeId, ChallengePurpose $purpose, string $binding): ?string
    {
        // Anything else never reaches a cache or lock key.
        if (1 !== preg_match(self::ID_PATTERN, $challengeId)) {
            return null;
        }

        $key = self::KEY_PREFIX . $challengeId;

        if (!$this->cache->hasItem($key)) {
            return null;
        }

        // getItem-then-deleteItem is not atomic on a PSR-6 pool: two near-simultaneous requests could both observe the
        // hit before either deletes, and both redeem the same challenge. A synced passkey often keeps signCount at 0
        // permanently, so the later counter check cannot catch that replay. Whoever waits here finds the challenge
        // gone below.
        //
        // One lock per id prefix, not per id: the default `flock` store never deletes its lock files, so a lock per
        // challenge would leave a file behind for each. That caps them at 256; the critical section is short enough to
        // wait for.
        $lock = $this->lockFactory->createLock(self::LOCK_PREFIX . substr($challengeId, 0, 2));
        $lock->acquire(true);

        try {
            $item = $this->cache->getItem($key);
            if (!$item->isHit()) {
                return null;
            }

            $this->cache->deleteItem($key); // delete first: single use even on later failure
            $data = $item->get();
            if (!\is_array($data) || ($data['expires'] ?? 0) < $this->clock->now()->getTimestamp()) {
                return null;
            }

            // A challenge is only valid for the ceremony it was issued for.
            if (($data['purpose'] ?? null) !== $purpose->value) {
                return null;
            }

            // Only in the browser it was handed out to: otherwise a cross-site POST could log a victim into the
            // attacker's account.
            $stored = $data['binding'] ?? null;
            if (!\is_string($stored) || !hash_equals($stored, hash('sha256', $binding))) {
                return null;
            }

            $encoded = $data['challenge'] ?? null;
            $raw = \is_string($encoded) ? base64_decode($encoded, true) : false;

            return false === $raw ? null : $raw;
        } finally {
            $lock->release();
        }
    }
}
