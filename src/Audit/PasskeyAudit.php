<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Audit;

use Psr\Log\LoggerInterface;
use Sulu\Bundle\ActivityBundle\Application\Collector\DomainEventCollectorInterface;
use Sulu\Component\Security\Authentication\UserInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Every change to a user's passkeys leaves three traces, because each covers a gap of the others. The activity log is in
 * the database, while the production log may drop a warning (a fingers_crossed handler only writes after an error). The
 * mail is what reaches the owner of the account: someone who took over a session is not going to read either log.
 */
final readonly class PasskeyAudit
{
    public function __construct(
        #[Autowire(service: 'sulu_activity.domain_event_collector')]
        private DomainEventCollectorInterface $activities,
        private LoggerInterface $logger,
        private MailerInterface $mailer,
        private TranslatorInterface $translator,
        #[Autowire('%sulu_passkey.sender%')]
        private ?string $sender,
    ) {
    }

    public function added(UserInterface $owner, string $id, string $name): void
    {
        $this->record('passkey_added', 'Passkey added', $owner, $owner, $id, $name);
        $this->mail($owner, 'added', $name);
    }

    public function removed(UserInterface $owner, ?UserInterface $actor, string $id, string $name): void
    {
        $this->record('passkey_removed', 'Passkey removed', $owner, $actor, $id, $name);
        $this->mail($owner, 'removed', $name);
    }

    private function record(string $type, string $message, UserInterface $owner, ?UserInterface $actor, string $id, string $name): void
    {
        $this->activities->collect(new PasskeyChangedEvent($type, $owner, $id, $name));
        $this->activities->dispatch();

        $this->logger->warning($message, [
            'actor' => $actor?->getUserIdentifier(),
            'user' => $owner->getUserIdentifier(),
            'passkey' => $id,
            'passkeyName' => $name,
        ]);
    }

    private function mail(UserInterface $owner, string $change, string $name): void
    {
        $recipient = method_exists($owner, 'getEmail') ? $owner->getEmail() : null;
        if (null === $this->sender || !\is_string($recipient) || '' === $recipient) {
            return;
        }

        $locale = $owner->getLocale();

        try {
            $this->mailer->send(new Email()
                ->from($this->sender)
                ->to($recipient)
                ->subject($this->translator->trans('sulu_passkey.mail_' . $change . '_subject', [], 'admin', $locale))
                ->text($this->translator->trans('sulu_passkey.mail_' . $change . '_body', ['{name}' => $name], 'admin', $locale)));
        } catch (\Throwable $exception) {
            // The change has happened. A mail server that is down must not turn it into an error page.
            $this->logger->error('Could not send the passkey notification', ['exception' => $exception]);
        }
    }
}
