<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\RelyingParty;

use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * The WebAuthn relying party comes from server configuration, never from the request Host header: an attacker-chosen
 * Host must not widen the allowed origins.
 */
final readonly class RelyingParty
{
    /** @var non-empty-string */
    private string $host;

    private string $origin;

    public function __construct(
        #[Autowire('%sulu_passkey.origin%')]
        string $configuredOrigin,
    ) {
        $parts = parse_url($configuredOrigin);
        if (!\is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            throw new \InvalidArgumentException('PASSKEY_ORIGIN must be an absolute URL.');
        }

        $host = strtolower($parts['host']);
        if ('' === $host) {
            throw new \InvalidArgumentException('PASSKEY_ORIGIN must be an absolute URL.');
        }

        $this->host = $host;
        $this->origin = $parts['scheme'] . '://' . $this->host . (isset($parts['port']) ? ':' . $parts['port'] : '');
    }

    /**
     * @throws UnsupportedHostException
     *
     * @return non-empty-string
     */
    public function id(string $requestHost): string
    {
        // Exactly this host: the origin is checked against the configured one alone, so a challenge handed out on any
        // other host, a subdomain included, could never be redeemed.
        if (strtolower(trim($requestHost)) !== $this->host) {
            throw new UnsupportedHostException();
        }

        return $this->host;
    }

    /**
     * @return list<string>
     */
    public function origins(): array
    {
        return [$this->origin];
    }
}
