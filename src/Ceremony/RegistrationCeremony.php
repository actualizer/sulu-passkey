<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Ceremony;

use Actualizer\SuluPasskey\Entity\PasskeyCredential;
use Actualizer\SuluPasskey\Challenge\ChallengePurpose;
use Actualizer\SuluPasskey\Challenge\ChallengeStore;
use Actualizer\SuluPasskey\Credential\CredentialStore;
use Actualizer\SuluPasskey\Credential\UserHandleProvider;
use Actualizer\SuluPasskey\RelyingParty\RelyingParty;
use Cose\Algorithms;
use Sulu\Component\Security\Authentication\UserInterface;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Registration ("attestation") ceremony: builds the creation options and verifies the returned attestation before
 * persisting the credential.
 */
final readonly class RegistrationCeremony
{
    public function __construct(
        private CeremonyFactory $ceremonyFactory,
        private ChallengeStore $challengeStore,
        private CredentialStore $credentials,
        private UserHandleProvider $userHandles,
        private RelyingParty $relyingParty,
        private WebauthnSerializer $serializer,
    ) {
    }

    /**
     * @return array{options: string, challengeId: string}
     */
    public function createOptions(UserInterface $user, string $host, string $binding): array
    {
        $challenge = random_bytes(32);
        $options = $this->serializer->serializeOptions($this->buildOptions($user, $host, $challenge));

        return [
            'options' => $options,
            'challengeId' => $this->challengeStore->issue($challenge, ChallengePurpose::Registration, binding: $binding),
        ];
    }

    public function verify(UserInterface $user, string $rawResponseJson, string $challengeId, string $host, string $binding, string $name): PasskeyCredential
    {
        if (mb_strlen($name) > CredentialStore::MAX_NAME_LENGTH) {
            throw new \RuntimeException('Credential name exceeds the maximum allowed length.');
        }

        $challenge = $this->challengeStore->consume($challengeId, ChallengePurpose::Registration, $binding);
        if (null === $challenge) {
            throw new \RuntimeException('Invalid or expired registration challenge.');
        }

        // Rebuild the options with the SAME challenge that was just consumed, so CheckChallenge compares against the
        // exact issued value.
        $options = $this->buildOptions($user, $host, $challenge);

        $credential = $this->serializer->deserializeCredential($rawResponseJson);
        $response = $credential->response;
        if (!$response instanceof AuthenticatorAttestationResponse) {
            throw new \RuntimeException('The response is not an attestation response.');
        }

        $record = AuthenticatorAttestationResponseValidator::create($this->ceremonyFactory->creation())
            ->check($response, $options, $host);

        $passkey = new PasskeyCredential(
            $user,
            // Taken from the options actually used, never re-resolved: the stored and the signed value must not be
            // able to drift apart.
            (string) $options->rp->id,
            $record->publicKeyCredentialId,
            $record->credentialPublicKey,
            $options->user->id,
            $record->counter,
            $record->aaguid->toRfc4122(),
            array_values($record->transports),
            '' !== $name ? $name : 'Passkey',
        );
        $this->credentials->save($passkey);

        return $passkey;
    }

    private function buildOptions(UserInterface $user, string $host, string $challenge): PublicKeyCredentialCreationOptions
    {
        $rpId = $this->relyingParty->id($host);

        return PublicKeyCredentialCreationOptions::create(
            new PublicKeyCredentialRpEntity($rpId, $rpId),
            // Cosmetic only: the label the browser's passkey manager shows. The user handle stays opaque.
            PublicKeyCredentialUserEntity::create($user->getUserIdentifier(), $this->userHandles->handleFor($user), $user->getUserIdentifier()),
            $challenge,
            [
                PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_ES256),
                PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_RS256),
            ],
            new AuthenticatorSelectionCriteria(
                userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            $this->excludeCredentials($user),
        );
    }

    /**
     * Every key the user already owns, so an authenticator refuses to enroll the same one twice. Both createOptions()
     * and verify() build through here, so the two option sets stay identical.
     *
     * @return list<PublicKeyCredentialDescriptor>
     */
    private function excludeCredentials(UserInterface $user): array
    {
        $descriptors = [];
        foreach ($this->credentials->listOwned($user) as $credential) {
            $descriptors[] = PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $credential->getCredentialId(),
                $credential->getTransports(),
            );
        }

        return $descriptors;
    }
}
