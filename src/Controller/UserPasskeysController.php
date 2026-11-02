<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Controller;

use Actualizer\SuluPasskey\Admin\PasskeyAdmin;
use Actualizer\SuluPasskey\Audit\PasskeyAudit;
use Actualizer\SuluPasskey\Credential\CredentialStore;
use Sulu\Component\Security\Authentication\UserInterface;
use Sulu\Component\Security\Authorization\PermissionTypes;
use Sulu\Component\Security\Authorization\SecurityCheckerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Lets an administrator take a passkey away from another user, the answer to an account takeover. It deletes only:
 * nobody can add a passkey to someone else's account.
 */
final class UserPasskeysController extends AbstractController
{
    public function __construct(
        private readonly CredentialStore $credentials,
        #[Autowire(service: 'sulu_security.security_checker')]
        private readonly SecurityCheckerInterface $securityChecker,
        private readonly PasskeyAudit $audit,
    ) {
    }

    #[Route('/admin/passkey/users/{userId}/credentials', name: 'sulu_passkey.user_credentials', requirements: ['userId' => '\d+'], methods: ['GET'])]
    public function list(int $userId): JsonResponse
    {
        $this->securityChecker->checkPermission(PasskeyAdmin::SECURITY_CONTEXT, PermissionTypes::VIEW);

        return new JsonResponse(['credentials' => array_map(CredentialView::of(...), $this->credentials->listOfUser($userId))]);
    }

    #[Route('/admin/passkey/users/{userId}/credentials/{id}', name: 'sulu_passkey.user_credential_delete', requirements: ['userId' => '\d+'], methods: ['DELETE'])]
    public function delete(int $userId, string $id): JsonResponse
    {
        $this->securityChecker->checkPermission(PasskeyAdmin::SECURITY_CONTEXT, PermissionTypes::DELETE);

        // Your own passkeys go through the profile, which asks for a confirmation. This route must not be the way around it.
        $actor = $this->getUser();
        if ($actor instanceof UserInterface && $actor->getId() === $userId) {
            return new JsonResponse(['message' => 'Use your profile for your own passkeys.'], Response::HTTP_FORBIDDEN);
        }

        $credential = $this->credentials->findOfUser($id, $userId);
        if (null === $credential) {
            throw $this->createNotFoundException();
        }

        $owner = $credential->getUser();
        $name = $credential->getName();
        $this->credentials->remove($credential);

        $this->audit->removed($owner, $actor instanceof UserInterface ? $actor : null, $id, $name);

        return new JsonResponse(null, Response::HTTP_NO_CONTENT);
    }
}
