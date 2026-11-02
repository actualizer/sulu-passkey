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

        $this->host = strtolower($parts['host']);
        $this->origin = $parts['scheme'] . '://' . $this->host . (isset($parts['port']) ? ':' . $parts['port'] : '');
    }

    /**
     * @throws UnsupportedHostException
     *
     * @return non-empty-string
     */
    public function id(string $requestHost): string
    {
        $host = strtolower(trim($requestHost));
        if ('' === $this->host || ($host !== $this->host && !str_ends_with($host, '.' . $this->host))) {
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
