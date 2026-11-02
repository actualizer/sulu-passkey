<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Controller;

use Actualizer\SuluPasskey\Audit\PasskeyAudit;
use Actualizer\SuluPasskey\Ceremony\AuthenticationCeremony;
use Actualizer\SuluPasskey\Ceremony\RegistrationCeremony;
use Actualizer\SuluPasskey\Credential\CredentialStore;
use Actualizer\SuluPasskey\Entity\PasskeyCredential;
use Actualizer\SuluPasskey\Http\ChallengeResponse;
use Actualizer\SuluPasskey\Http\JsonPayload;
use Actualizer\SuluPasskey\Http\TooManyRequests;
use Actualizer\SuluPasskey\Security\RecentReauthentication;
use Actualizer\SuluPasskey\Security\SessionBinding;
use Actualizer\SuluPasskey\Security\SessionPassword;
use Psr\Log\LoggerInterface;
use Sulu\Component\Security\Authentication\UserInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;

/**
 * The signed-in user's own passkeys. Everything here is below /admin, which Sulu's access_control keeps behind a login.
 */
final class ProfileController extends AbstractController
{
    public function __construct(
        private readonly AuthenticationCeremony $authentication,
        private readonly RegistrationCeremony $registration,
        private readonly CredentialStore $credentials,
        private readonly RecentReauthentication $reauthentication,
        private readonly SessionPassword $sessionPassword,
        private readonly UserPasswordHasherInterface $passwords,
        private readonly PasskeyAudit $audit,
        private readonly LoggerInterface $logger,
        #[Autowire(service: 'limiter.sulu_passkey_reauthentication')]
        private readonly RateLimiterFactoryInterface $limiter,
    ) {
    }

    #[Route('/admin/passkey/credentials', name: 'sulu_passkey.credentials', methods: ['GET'])]
    public function credentials(): JsonResponse
    {
        return new JsonResponse(['credentials' => array_map(CredentialView::of(...), $this->credentials->listOwned($this->suluUser()))]);
    }

    #[Route('/admin/passkey/credentials/{id}', name: 'sulu_passkey.credential_delete', methods: ['DELETE'])]
    public function deleteCredential(Request $request, string $id): JsonResponse
    {
        $user = $this->suluUser();
        if (!$this->reauthentication->holdsFor($request, $user)) {
            return $this->refused('Reauthentication required.');
        }

        // Looked up through the owner: a foreign id answers exactly like an unknown one.
        $credential = $this->credentials->findOfUser($id, $user->getId());
        if (null === $credential) {
            throw $this->createNotFoundException();
        }

        $name = $credential->getName();
        $this->credentials->remove($credential);
        $this->reauthentication->forget($request);
        $this->audit->removed($user, $user, $id, $name);

        return new JsonResponse(null, Response::HTTP_NO_CONTENT);
    }

    #[Route('/admin/passkey/reauth/options', name: 'sulu_passkey.reauth_options', methods: ['POST'])]
    public function reauthenticationOptions(Request $request): JsonResponse
    {
        return ChallengeResponse::of($this->authentication->createReauthenticationOptions($this->suluUser(), $request->getHost(), SessionBinding::of($request)));
    }

    /**
     * Takes the password or an assertion of one of the user's own passkeys. Answers 403 on failure: a 401 would make
     * Sulu's admin show its login.
     */
    #[Route('/admin/passkey/reauth', name: 'sulu_passkey.reauth', methods: ['POST'])]
    public function reauthenticate(Request $request): JsonResponse
    {
        $user = $this->suluUser();

        $password = JsonPayload::string($request, 'password');
        if (null !== $password) {
            $limiter = $this->limiter->create((string) $user->getId());
            $limit = $limiter->consume();
            if (!$limit->isAccepted()) {
                return TooManyRequests::after($limit);
            }

            if (
                !$user instanceof PasswordAuthenticatedUserInterface
                || !$this->passwords->isPasswordValid($user, $password)
                || !$this->sessionPassword->isUnchanged($request, $user)
            ) {
                return $this->refused('Reauthentication failed.');
            }

            $limiter->reset();
            $this->reauthentication->record($request, $user);

            return new JsonResponse(null, Response::HTTP_NO_CONTENT);
        }

        $credential = JsonPayload::string($request, 'credential');
        $challengeId = JsonPayload::string($request, 'challengeId');
        if (null === $credential || null === $challengeId) {
            return $this->refused('Reauthentication failed.');
        }

        try {
            $this->authentication->verifyReauthentication($user, $credential, $challengeId, $request->getHost(), SessionBinding::of($request));
        } catch (\Throwable $exception) {
            $this->logger->notice('Passkey reauthentication failed', ['exception' => $exception]);

            return $this->refused('Reauthentication failed.');
        }

        $this->reauthentication->record($request, $user);

        return new JsonResponse(null, Response::HTTP_NO_CONTENT);
    }

    #[Route('/admin/passkey/register/options', name: 'sulu_passkey.register_options', methods: ['POST'])]
    public function registerOptions(Request $request): JsonResponse
    {
        $user = $this->suluUser();
        if (!$this->reauthentication->holdsFor($request, $user)) {
            return $this->refused('Reauthentication required.');
        }

        return ChallengeResponse::of($this->registration->createOptions($user, $request->getHost(), SessionBinding::of($request)));
    }

    #[Route('/admin/passkey/register', name: 'sulu_passkey.register', methods: ['POST'])]
    public function register(Request $request): JsonResponse
    {
        $user = $this->suluUser();
        if (!$this->reauthentication->holdsFor($request, $user)) {
            return $this->refused('Reauthentication required.');
        }

        $credential = JsonPayload::string($request, 'credential');
        $challengeId = JsonPayload::string($request, 'challengeId');
        $name = JsonPayload::string($request, 'name') ?? '';
        if (null === $credential || null === $challengeId) {
            return new JsonResponse(['message' => 'Malformed request.'], Response::HTTP_BAD_REQUEST);
        }

        try {
            $passkey = $this->registration->verify($user, $credential, $challengeId, $request->getHost(), SessionBinding::of($request), trim($name));
        } catch (\Throwable $exception) {
            $this->logger->notice('Passkey registration failed', ['exception' => $exception]);
            // The admin confirms again for every attempt, so a confirmation has no reason to outlive a failed one.
            $this->reauthentication->forget($request);

            return new JsonResponse(['message' => 'Passkey registration failed.'], Response::HTTP_BAD_REQUEST);
        }

        $this->reauthentication->forget($request);
        $this->audit->added($user, $passkey->getId(), $passkey->getName());

        return new JsonResponse(['ok' => true]);
    }

    private function refused(string $message): JsonResponse
    {
        return new JsonResponse(['message' => $message], Response::HTTP_FORBIDDEN);
    }

    private function suluUser(): UserInterface
    {
        $user = $this->getUser();
        if (!$user instanceof UserInterface) {
            throw $this->createAccessDeniedException();
        }

        return $user;
    }
}
