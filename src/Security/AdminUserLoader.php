<?php

declare(strict_types=1);

namespace Actualizer\SuluPasskey\Security;

use Sulu\Bundle\SecurityBundle\System\SystemStoreInterface;
use Sulu\Component\Security\Authentication\UserInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Security::login() asks no user provider, so what Sulu's provider checks at a login has to be asked for here: disabled,
 * locked, and a role in the admin system.
 *
 * By id, not with loadUserByIdentifier(): that matches username OR e-mail, so another user's e-mail address equal to this
 * username would block the login, or find the wrong account.
 */
final readonly class AdminUserLoader
{
    public function __construct(
        /** @var UserProviderInterface<UserInterface> */
        #[Autowire(service: 'sulu_security.user_provider')]
        private UserProviderInterface $users,
        #[Autowire(service: 'sulu_security.system_store')]
        private SystemStoreInterface $systems,
    ) {
    }

    public function load(UserInterface $owner): UserInterface
    {
        $user = $this->users->refreshUser($owner);
        if ($user->getId() !== $owner->getId()) {
            throw new UserNotFoundException();
        }

        foreach ($user->getRoleObjects() as $role) {
            if ($role->getSystem() === $this->systems->getSystem()) {
                return $user;
            }
        }

        throw new UserNotFoundException();
    }
}
