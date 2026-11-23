<?php

declare(strict_types=1);

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use Actualizer\SuluPasskey\Admin\PasskeyAdmin;
use Actualizer\SuluPasskey\Security\BrowserBinding;
use Actualizer\SuluPasskey\Security\PasskeySessionGuard;
use Actualizer\SuluPasskey\Security\PasskeyTokenListener;
use Actualizer\SuluPasskey\Security\SessionPasswordListener;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Http\Event\AuthenticationTokenCreatedEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

return static function (ContainerConfigurator $container): void {
    $services = $container->services()->defaults()->autowire()->autoconfigure();

    $services->load('Actualizer\\SuluPasskey\\', '../src/')
        ->exclude([
            '../src/Audit/PasskeyChangedEvent.php',
            '../src/Challenge/ChallengePurpose.php',
            '../src/Controller/CredentialView.php',
            '../src/Entity/',
            '../src/Http/',
            '../src/RelyingParty/UnsupportedHostException.php',
            '../src/Security/PasskeyToken.php',
            '../src/SuluPasskeyBundle.php',
        ]);

    $services->set(PasskeyAdmin::class)->tag('sulu.admin')->tag('sulu.context', ['context' => 'admin']);

    $services->set(PasskeyTokenListener::class)
        ->tag('kernel.event_listener', [
            'event' => AuthenticationTokenCreatedEvent::class,
            'dispatcher' => 'security.event_dispatcher.' . PasskeyTokenListener::FIREWALL,
            'priority' => PasskeyTokenListener::PRIORITY,
        ]);

    $services->set(SessionPasswordListener::class)
        ->tag('kernel.event_listener', [
            'event' => LoginSuccessEvent::class,
            'dispatcher' => 'security.event_dispatcher.' . PasskeyTokenListener::FIREWALL,
            'priority' => SessionPasswordListener::PRIORITY,
        ]);

    $services->set(BrowserBinding::class)
        ->tag('kernel.event_listener', ['event' => KernelEvents::RESPONSE]);

    $services->set(PasskeySessionGuard::class)
        ->tag('kernel.event_listener', ['event' => KernelEvents::REQUEST, 'priority' => PasskeySessionGuard::PRIORITY]);
};
