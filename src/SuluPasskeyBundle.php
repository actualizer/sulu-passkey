<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey;

use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

final class SuluPasskeyBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->scalarNode('origin')
                    ->info('Absolute URL of the admin, e.g. https://cms.example.com. Its host becomes the WebAuthn relying party.')
                    ->defaultValue('%env(PASSKEY_ORIGIN)%')
                ->end()
                ->scalarNode('sender')
                    ->info('From address of the mail a user gets when a passkey is added to or removed from their account. Without one, no mail is sent.')
                    ->defaultNull()
                ->end()
            ->end();
    }

    /**
     * @param array{origin: string, sender: string|null} $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->parameters()
            ->set('sulu_passkey.origin', $config['origin'])
            ->set('sulu_passkey.sender', $config['sender']);

        // Everything here is admin code, and the website kernel may not have a firewall to attach it to.
        if ('admin' === $builder->getParameter('sulu.context')) {
            $container->import('../config/services.php');
        }
    }

    public function prependExtension(ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $builder->prependExtensionConfig('framework', [
            'cache' => [
                'pools' => [
                    // Every passkey flow spans two requests, so a cache:clear must not drop its challenges.
                    'sulu_passkey.challenge_pool' => ['adapter' => 'cache.adapter.filesystem', 'default_lifetime' => 300],
                ],
            ],
            'rate_limiter' => [
                // Per client (an IPv4 address or an IPv6 /64). Each login makes two requests. Without a lock: the default
                // flock store would leave one file per client address behind for good, and a race only costs a request.
                'sulu_passkey_login' => ['policy' => 'sliding_window', 'limit' => 30, 'interval' => '1 minute', 'lock_factory' => null],
                // All clients together.
                'sulu_passkey_login_ceiling' => ['policy' => 'sliding_window', 'limit' => 600, 'interval' => '1 minute'],
                // Per user: a stolen session must not be able to guess the password behind it.
                'sulu_passkey_reauthentication' => ['policy' => 'fixed_window', 'limit' => 5, 'interval' => '15 minutes'],
            ],
        ]);

        // Appended, not prepended: Sulu merges forms in the order of these directories, and a prepended one would put the
        // passkeys above Sulu's own fields.
        if ($builder->hasExtension('sulu_admin')) {
            $builder->loadFromExtension('sulu_admin', [
                'forms' => ['directories' => [\dirname(__DIR__) . '/config/forms']],
            ]);
        }

        $builder->prependExtensionConfig('doctrine', [
            'orm' => [
                'mappings' => [
                    'SuluPasskeyBundle' => [
                        'type' => 'attribute',
                        'is_bundle' => false,
                        'dir' => \dirname(__DIR__) . '/src/Entity',
                        'prefix' => 'Actualizer\SuluPasskey\Entity',
                        'alias' => 'SuluPasskeyBundle',
                    ],
                ],
            ],
        ]);

        if ($builder->hasExtension('doctrine_migrations')) {
            $builder->prependExtensionConfig('doctrine_migrations', [
                'migrations_paths' => ['Actualizer\SuluPasskey\Migrations' => \dirname(__DIR__) . '/migrations'],
            ]);
        }
    }
}
