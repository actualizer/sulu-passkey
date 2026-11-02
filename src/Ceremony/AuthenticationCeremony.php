<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Ceremony;

use Actualizer\SuluPasskey\Entity\PasskeyCredential;
use Actualizer\SuluPasskey\Challenge\ChallengePurpose;
use Actualizer\SuluPasskey\Challenge\ChallengeStore;
use Actualizer\SuluPasskey\Credential\CredentialStore;
use Actualizer\SuluPasskey\RelyingParty\RelyingParty;
use Psr\Log\LoggerInterface;
use Sulu\Component\Security\Authentication\UserInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\CredentialRecord;
use Webauthn\Exception\CounterException;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Authentication ("assertion") ceremony: builds usernameless request options and verifies the returned assertion.
 *
 * The account comes from the STORED credential's owner, never from the userHandle carried in the assertion.
 *
 * Unlike Shopware's stateless token endpoint, a Sulu login creates a session, so every challenge is bound to the
 * browser session that requested it. Without that, a cross-site POST of an attacker's assertion could sign a victim
 * into the attacker's account.
 */
final readonly class AuthenticationCeremony
{
    public function __construct(
        private CeremonyFactory $ceremonyFactory,
        private ChallengeStore $challengeStore,
        private CredentialStore $credentials,
        private RelyingParty $relyingParty,
        private WebauthnSerializer $serializer,
        private LoggerInterface $logger,
    ) {
    }

    /**
     * @return array{options: string, challengeId: string}
     */
    public function createOptions(string $host, string $binding): array
    {
        $challenge = random_bytes(32);
        // Built first: a refused host must not leave a challenge behind.
        $options = $this->serializer->serializeOptions($this->buildOptions($host, $challenge));

        return [
            'options' => $options,
            'challengeId' => $this->challengeStore->issue($challenge, ChallengePurpose::Authentication, binding: $binding),
        ];
    }

    /**
     * The same ceremony for a user who is already signed in and has to prove it is still them. It has a challenge
     * purpose of its own, so a login challenge cannot stand in for it.
     *
     * @return array{options: string, challengeId: string}
     */
    public function createReauthenticationOptions(UserInterface $user, string $host, string $binding): array
    {
        $challenge = random_bytes(32);
        $options = $this->serializer->serializeOptions($this->buildOptions($host, $challenge, $this->descriptors($user)));

        return [
            'options' => $options,
            'challengeId' => $this->challengeStore->issue($challenge, ChallengePurpose::Reauthentication, binding: $binding),
        ];
    }

    public function verifyReauthentication(UserInterface $user, string $rawResponseJson, string $challengeId, string $host, string $binding): void
    {
        $this->check($rawResponseJson, $challengeId, $host, $binding, ChallengePurpose::Reauthentication, $user);
    }

    /**
     * Writes the sign count (clone detection must not wait for the caller) but never `lastUsedAt`: the caller stamps
     * that once it has accepted the account.
     */
    public function verify(string $rawResponseJson, string $challengeId, string $host, string $binding): PasskeyCredential
    {
        return $this->check($rawResponseJson, $challengeId, $host, $binding, ChallengePurpose::Authentication, null);
    }

    private function check(string $rawResponseJson, string $challengeId, string $host, string $binding, ChallengePurpose $purpose, ?UserInterface $owner): PasskeyCredential
    {
        $challenge = $this->challengeStore->consume($challengeId, $purpose, $binding);
        if (null === $challenge) {
            throw new \RuntimeException('Invalid or expired authentication challenge.');
        }

        $options = $this->buildOptions($host, $challenge);

        $credential = $this->serializer->deserializeCredential($rawResponseJson);
        $response = $credential->response;
        if (!$response instanceof AuthenticatorAssertionResponse) {
            throw new \RuntimeException('The response is not an assertion response.');
        }

        $passkey = $this->credentials->findOneByCredentialId($credential->rawId);
        if (null === $passkey) {
            throw new \RuntimeException('Unknown credential.');
        }

        if (null !== $owner && $passkey->getUser()->getId() !== $owner->getId()) {
            throw new \RuntimeException('The credential belongs to another user.');
        }

        // A credential is bound to the relying party it was registered for. The library validates the assertion's
        // rpIdHash against the rp id of the options, not the stored one.
        if ($passkey->getRpId() !== $options->rpId) {
            throw new \RuntimeException('Credential is bound to a different relying party.');
        }

        $validator = AuthenticatorAssertionResponseValidator::create($this->ceremonyFactory->request());
        // Last argument is the expected user handle: the validator enforces that the assertion's own userHandle
        // matches the stored one.
        try {
            $validator->check($this->toCredentialRecord($passkey), $response, $options, $host, $passkey->getUserHandle());
        } catch (CounterException $exception) {
            $this->markPossiblyCloned($passkey);

            throw $exception;
        }

        $passkey->setSignCount($response->authenticatorData->signCount);
        $this->credentials->save($passkey);

        return $passkey;
    }

    /**
     * A signature counter that did not go up means another copy of the key may be signing too. The login stays
     * refused; the credential is only marked, not disabled, because some authenticators reset their counter.
     *
     * WARNING although this is a public route: webauthn-lib checks the signature before the counter, so only a
     * genuinely signed assertion of a stored key gets here and bots cannot flood it.
     */
    private function markPossiblyCloned(PasskeyCredential $passkey): void
    {
        $this->logger->warning('Passkey signature counter did not increase; the passkey may be cloned', [
            'credentialId' => $passkey->getId(),
        ]);

        $passkey->setCloneWarningAt(new \DateTimeImmutable());
        $this->credentials->save($passkey);
    }

    /**
     * @param list<PublicKeyCredentialDescriptor> $allowCredentials
     */
    private function buildOptions(string $host, string $challenge, array $allowCredentials = []): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions::create(
            $challenge,
            $this->relyingParty->id($host),
            $allowCredentials,
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        );
    }

    /**
     * @return list<PublicKeyCredentialDescriptor>
     */
    private function descriptors(UserInterface $user): array
    {
        return array_map(static fn (PasskeyCredential $credential): PublicKeyCredentialDescriptor => PublicKeyCredentialDescriptor::create(
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $credential->getCredentialId(),
            $credential->getTransports(),
        ), $this->credentials->listOwned($user));
    }

    private function toCredentialRecord(PasskeyCredential $passkey): CredentialRecord
    {
        return CredentialRecord::create(
            $passkey->getCredentialId(),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $passkey->getTransports(),
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString($passkey->getAaguid()),
            $passkey->getPublicKey(),
            $passkey->getUserHandle(),
            $passkey->getSignCount(),
        );
    }
}
