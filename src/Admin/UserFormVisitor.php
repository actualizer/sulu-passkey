<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Admin;

use Sulu\Bundle\AdminBundle\Metadata\FormMetadata\FormMetadata;
use Sulu\Bundle\AdminBundle\Metadata\FormMetadata\FormMetadataVisitorInterface;
use Sulu\Component\Security\Authorization\PermissionTypes;
use Sulu\Component\Security\Authorization\SecurityCheckerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Sulu's form conditions cannot ask for a permission, so the field is taken out of the form for those without it. This
 * only tidies the form up: UserPasskeysController checks the permission on every request itself.
 */
final readonly class UserFormVisitor implements FormMetadataVisitorInterface
{
    private const string FORM = 'user_details';

    private const string FIELD = 'user_passkeys';

    public function __construct(
        #[Autowire(service: 'sulu_security.security_checker')]
        private SecurityCheckerInterface $securityChecker,
    ) {
    }

    public function visitFormMetadata(FormMetadata $formMetadata, string $locale, array $metadataOptions = []): void
    {
        if (self::FORM !== $formMetadata->getKey() || $this->securityChecker->hasPermission(PasskeyAdmin::SECURITY_CONTEXT, PermissionTypes::VIEW)) {
            return;
        }

        $items = $formMetadata->getItems();
        unset($items[self::FIELD]);
        $formMetadata->setItems($items);
    }
}
