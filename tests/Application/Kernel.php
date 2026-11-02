<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Application;

use Actualizer\SuluPasskey\SuluPasskeyBundle;
use Scheb\TwoFactorBundle\SchebTwoFactorBundle;
use Sulu\Bundle\TestBundle\Kernel\SuluTestKernel;
use Sulu\Bundle\TestBundle\SuluTestBundle;
use Symfony\Component\Config\Loader\LoaderInterface;

/**
 * A Sulu admin with the firewall of the Sulu skeleton (json_login plus scheb's two_factor), which SuluTestBundle's own
 * config (http_basic and a fake user provider) would hide.
 */
final class Kernel extends SuluTestKernel
{
    public function registerBundles(): iterable
    {
        yield from parent::registerBundles();
        yield new SuluPasskeyBundle();

        if (self::CONTEXT_ADMIN === $this->getContext()) {
            yield new SchebTwoFactorBundle();
        }
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $config = SuluTestBundle::getConfigDir();
        $loader->load($config . '/context_' . $this->getContext() . '.yml');
        $loader->load($config . '/symfony-6.yml');
        $loader->load(__DIR__ . '/config/config.yaml');

        if (self::CONTEXT_ADMIN === $this->getContext()) {
            $loader->load(__DIR__ . '/config/admin.yaml');
        }
    }
}
