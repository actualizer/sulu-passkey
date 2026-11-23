<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Controller;

use Actualizer\SuluPasskey\Ceremony\AuthenticationCeremony;
use Actualizer\SuluPasskey\Credential\CredentialStore;
use Actualizer\SuluPasskey\Http\ChallengeResponse;
use Actualizer\SuluPasskey\Http\JsonPayload;
use Actualizer\SuluPasskey\Http\Refusal;
use Actualizer\SuluPasskey\Http\TooManyRequests;
use Actualizer\SuluPasskey\Security\AdminUserLoader;
use Actualizer\SuluPasskey\Security\PasskeyTokenListener;
use Actualizer\SuluPasskey\Security\BrowserBinding;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The public side of the login. /admin/p/ is the one path Sulu's access_control already leaves open, which is why no
 * security.yaml change is needed. Its preview routes (/admin/p/{token} and /admin/p/{token}/render) match neither of
 * the two paths below.
 */
final class LoginController extends AbstractController
{
    public function __construct(
        private readonly AuthenticationCeremony $ceremony,
        private readonly CredentialStore $credentials,
        private readonly LoggerInterface $logger,
        private readonly Security $security,
        private readonly AdminUserLoader $users,
        #[Autowire(service: 'limiter.sulu_passkey_login')]
        private readonly RateLimiterFactoryInterface $limiter,
        #[Autowire(service: 'limiter.sulu_passkey_login_ceiling')]
        private readonly RateLimiterFactoryInterface $ceiling,
    ) {
    }

    #[Route('/admin/p/passkey/login/options', name: 'sulu_passkey.login_options', methods: ['POST'])]
    public function options(Request $request): JsonResponse
    {
        return $this->refusedByLimit($request)
            ?? ChallengeResponse::of($this->ceremony->createOptions($request->getHost(), BrowserBinding::of($request)));
    }

    #[Route('/admin/p/passkey/login', name: 'sulu_passkey.login', methods: ['POST'])]
    public function login(Request $request): JsonResponse
    {
        $refused = $this->refusedByLimit($request);
        if (null !== $refused) {
            return $refused;
        }

        $credential = JsonPayload::string($request, 'credential');
        $challengeId = JsonPayload::string($request, 'challengeId');
        if (null === $credential || null === $challengeId) {
            return $this->failed();
        }

        try {
            $passkey = $this->ceremony->verify($credential, $challengeId, $request->getHost(), BrowserBinding::of($request));
            $user = $this->users->load($passkey->getUser());
        } catch (\Throwable $exception) {
            if (!Refusal::covers($exception)) {
                throw $exception;
            }

            $this->logger->notice('Passkey admin authentication failed', Refusal::context($exception));

            return $this->failed();
        }

        // json_login's success response is dropped: it depends on the request type, and this route only speaks JSON.
        $this->security->login($user, 'json_login', PasskeyTokenListener::FIREWALL, attributes: [PasskeyTokenListener::CREDENTIAL_ATTRIBUTE => $passkey->getId()]);

        // Stamped only now: a refused login must not look like a recent use.
        $passkey->setLastUsedAt(new \DateTimeImmutable());
        $this->credentials->save($passkey);

        // The fields of Sulu's own login answer: the admin continues on the open page with them.
        return new JsonResponse([
            'url' => $this->generateUrl('sulu_admin'),
            'username' => $user->getUserIdentifier(),
            'completed' => true,
        ]);
    }

    private function refusedByLimit(Request $request): ?JsonResponse
    {
        // The whole /64 counts as one client: that is what a single IPv6 connection gets to choose its address from.
        $client = IpUtils::anonymize($request->getClientIp() ?? '0.0.0.0', 0, 8);
        $limit = $this->limiter->create($client)->consume();
        if (!$limit->isAccepted()) {
            return TooManyRequests::after($limit);
        }

        // Both routes write for a request nobody has to authenticate, so all clients together get a ceiling as well. Only
        // after the check above: a client that is already refused must not use it up for everyone else.
        $ceiling = $this->ceiling->create('all')->consume();

        return $ceiling->isAccepted() ? null : TooManyRequests::after($ceiling);
    }

    private function failed(): JsonResponse
    {
        return new JsonResponse(['message' => 'Passkey login failed.'], Response::HTTP_UNAUTHORIZED);
    }
}
