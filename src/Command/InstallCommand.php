<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Does the three project edits the bundle cannot do from inside `vendor`. Safe to run again: what is there stays.
 */
#[AsCommand(name: 'sulu-passkey:install', description: 'Wires the passkey bundle into the admin build and the routes')]
final class InstallCommand extends Command
{
    private const string PACKAGE = 'sulu-passkey-bundle';

    private const string PACKAGE_PATH = 'file:../../vendor/actualizer/sulu-passkey/assets/admin';

    private const string ROUTES = <<<'YAML'
        sulu_passkey:
            resource: '@SuluPasskeyBundle/config/routes.yaml'

        YAML;

    public function __construct(
        #[Autowire('%kernel.project_dir%')]
        private readonly string $projectDir,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $packageFile = $this->projectDir . '/assets/admin/package.json';
        $appFile = $this->projectDir . '/assets/admin/app.js';
        if (!is_file($packageFile) || !is_file($appFile)) {
            $io->error('No assets/admin/package.json and app.js found. Is this a Sulu project?');

            return self::FAILURE;
        }

        $this->addPackage($packageFile);
        $this->addImport($appFile);
        $this->addRoutes($this->projectDir . '/config/routes/sulu_passkey_admin.yaml');

        $io->success('Done.');
        $io->listing([
            'bin/adminconsole sulu:admin:update-build',
            'bin/adminconsole doctrine:migrations:migrate',
        ]);

        return self::SUCCESS;
    }

    private function addPackage(string $file): void
    {
        $package = json_decode((string) file_get_contents($file), true, flags: \JSON_THROW_ON_ERROR);
        \assert(\is_array($package));
        $dependencies = \is_array($package['dependencies'] ?? null) ? $package['dependencies'] : [];
        if (isset($dependencies[self::PACKAGE])) {
            return;
        }

        $dependencies[self::PACKAGE] = self::PACKAGE_PATH;
        ksort($dependencies);
        $package['dependencies'] = $dependencies;

        file_put_contents($file, json_encode($package, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_THROW_ON_ERROR) . "\n");
    }

    private function addImport(string $file): void
    {
        $content = (string) file_get_contents($file);
        if (str_contains($content, self::PACKAGE)) {
            return;
        }

        file_put_contents($file, rtrim($content, "\n") . "\nimport '" . self::PACKAGE . "';\n");
    }

    private function addRoutes(string $file): void
    {
        if (!is_file($file)) {
            file_put_contents($file, self::ROUTES);
        }
    }
}
