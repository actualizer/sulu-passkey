<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Security;

use Actualizer\SuluPasskey\Credential\CredentialStore;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * Ends the session of a passkey that is gone, on its next request: deleting a passkey is how an administrator answers
 * an account takeover, and a session signed in with it must not survive that.
 *
 * Runs right after the firewall (priority 8), so the token is loaded and no controller has seen the request yet.
 */
final readonly class PasskeySessionGuard
{
    public const int PRIORITY = 7;

    public function __construct(
        private TokenStorageInterface $tokenStorage,
        private CredentialStore $credentials,
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        $request = $event->getRequest();

        // Without a session there is no token, and asking for one would start the lazy firewall on public pages.
        if (!$event->isMainRequest() || !$request->hasPreviousSession()) {
            return;
        }

        $token = $this->tokenStorage->getToken();
        if (!$token instanceof PasskeyToken || $this->credentials->exists($token->getCredentialId())) {
            return;
        }

        $this->tokenStorage->setToken(null);
        $request->getSession()->invalidate();

        // The admin's JavaScript shows its login on a 401, a browser navigation needs a page to land on.
        $event->setResponse(\in_array('text/html', $request->getAcceptableContentTypes(), true)
            ? new RedirectResponse('/admin')
            : new Response('', Response::HTTP_UNAUTHORIZED));
    }
}
