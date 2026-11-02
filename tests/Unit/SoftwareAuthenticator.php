<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Unit;

/**
 * A real ES256 authenticator in software: the ceremonies verify genuine signatures, nothing is mocked.
 */
final class SoftwareAuthenticator
{
    private const int FLAG_USER_PRESENT = 0x01;

    private const int FLAG_USER_VERIFIED = 0x04;

    private const int FLAG_ATTESTED_CREDENTIAL = 0x40;

    private readonly \OpenSSLAsymmetricKey $key;

    private readonly string $credentialId;

    private string $userHandle = '';

    public function __construct(private readonly string $rpId, public string $origin, public int $counter = 0)
    {
        $key = openssl_pkey_new(['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        if (false === $key) {
            throw new \RuntimeException('Could not create a key.');
        }

        $this->key = $key;
        $this->credentialId = random_bytes(32);
    }

    /**
     * @param array{challenge: string, user: array{id: string}} $options
     */
    public function register(array $options): string
    {
        $this->userHandle = self::decode($options['user']['id']);
        $authenticatorData = hash('sha256', $this->rpId, true)
            . \chr(self::FLAG_USER_PRESENT | self::FLAG_USER_VERIFIED | self::FLAG_ATTESTED_CREDENTIAL)
            . pack('N', $this->counter)
            . str_repeat("\0", 16)
            . pack('n', \strlen($this->credentialId)) . $this->credentialId
            . $this->coseKey();

        return (string) json_encode([
            'id' => self::encode($this->credentialId),
            'rawId' => self::encode($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => self::encode($this->clientData('webauthn.create', $options['challenge'])),
                'attestationObject' => self::encode(self::attestationObject($authenticatorData)),
                'transports' => ['internal'],
            ],
            'clientExtensionResults' => [],
        ]);
    }

    /**
     * @param array{challenge: string} $options
     */
    public function sign(array $options): string
    {
        $authenticatorData = hash('sha256', $this->rpId, true)
            . \chr(self::FLAG_USER_PRESENT | self::FLAG_USER_VERIFIED)
            . pack('N', $this->counter);
        $clientData = $this->clientData('webauthn.get', $options['challenge']);
        $signature = '';
        openssl_sign($authenticatorData . hash('sha256', $clientData, true), $signature, $this->key, \OPENSSL_ALGO_SHA256);
        \assert(\is_string($signature));

        return (string) json_encode([
            'id' => self::encode($this->credentialId),
            'rawId' => self::encode($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => self::encode($clientData),
                'authenticatorData' => self::encode($authenticatorData),
                'signature' => self::encode($signature),
                'userHandle' => self::encode($this->userHandle),
            ],
            'clientExtensionResults' => [],
        ]);
    }

    private function clientData(string $type, string $challenge): string
    {
        return (string) json_encode(['type' => $type, 'challenge' => $challenge, 'origin' => $this->origin, 'crossOrigin' => false], \JSON_UNESCAPED_SLASHES);
    }

    private function coseKey(): string
    {
        $details = openssl_pkey_get_details($this->key);
        if (false === $details || !\is_array($details['ec'] ?? null)) {
            throw new \RuntimeException('Could not read the key.');
        }

        $coordinate = static fn (mixed $value): string => str_pad(\is_string($value) ? $value : '', 32, "\0", \STR_PAD_LEFT);

        // CBOR map {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
        return "\xA5\x01\x02\x03\x26\x20\x01"
            . "\x21\x58\x20" . $coordinate($details['ec']['x'])
            . "\x22\x58\x20" . $coordinate($details['ec']['y']);
    }

    private static function attestationObject(string $authenticatorData): string
    {
        // CBOR map {"fmt": "none", "attStmt": {}, "authData": bytes}
        return "\xA3\x63fmt\x64none\x67attStmt\xA0\x68authData\x59" . pack('n', \strlen($authenticatorData)) . $authenticatorData;
    }

    private static function encode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private static function decode(string $value): string
    {
        return (string) base64_decode(strtr($value, '-_', '+/'), true);
    }
}
