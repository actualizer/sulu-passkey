<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Tests\Unit;

use Actualizer\SuluPasskey\Command\InstallCommand;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;

final class InstallCommandTest extends TestCase
{
    private string $project;

    protected function setUp(): void
    {
        $this->project = sys_get_temp_dir() . '/sulu-passkey-install-' . bin2hex(random_bytes(6));
        mkdir($this->project . '/assets/admin', recursive: true);
        mkdir($this->project . '/config/routes', recursive: true);
        file_put_contents($this->project . '/assets/admin/package.json', json_encode(['name' => 'app', 'dependencies' => ['react' => '^17.0.0']]));
        file_put_contents($this->project . '/assets/admin/app.js', "// project code\n");
    }

    protected function tearDown(): void
    {
        new Filesystem()->remove($this->project);
    }

    public function testItWiresTheProjectUp(): void
    {
        $this->install();

        /** @var array{dependencies: array<string, string>} $package */
        $package = json_decode((string) file_get_contents($this->project . '/assets/admin/package.json'), true);
        self::assertSame('file:../../vendor/actualizer/sulu-passkey/assets/admin', $package['dependencies']['sulu-passkey-bundle']);
        self::assertSame('^17.0.0', $package['dependencies']['react']);
        self::assertSame("// project code\nimport 'sulu-passkey-bundle';\n", file_get_contents($this->project . '/assets/admin/app.js'));
        self::assertStringContainsString('@SuluPasskeyBundle/config/routes.yaml', (string) file_get_contents($this->project . '/config/routes/sulu_passkey_admin.yaml'));
    }

    public function testASecondRunChangesNothing(): void
    {
        $this->install();
        $files = ['/assets/admin/package.json', '/assets/admin/app.js', '/config/routes/sulu_passkey_admin.yaml'];
        $before = array_map(fn (string $file) => file_get_contents($this->project . $file), $files);

        $this->install();

        self::assertSame($before, array_map(fn (string $file) => file_get_contents($this->project . $file), $files));
    }

    public function testItKeepsARouteFileTheProjectChanged(): void
    {
        $this->install();
        file_put_contents($this->project . '/config/routes/sulu_passkey_admin.yaml', "# mine\n");

        $this->install();

        self::assertSame("# mine\n", file_get_contents($this->project . '/config/routes/sulu_passkey_admin.yaml'));
    }

    public function testItFailsOutsideOfASuluProject(): void
    {
        unlink($this->project . '/assets/admin/package.json');

        $tester = new CommandTester(new InstallCommand($this->project));

        self::assertSame(1, $tester->execute([]));
        self::assertFileDoesNotExist($this->project . '/config/routes/sulu_passkey_admin.yaml');
    }

    private function install(): void
    {
        self::assertSame(0, new CommandTester(new InstallCommand($this->project))->execute([]));
    }
}
