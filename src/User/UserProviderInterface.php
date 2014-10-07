<?php

namespace Renegare\Soauth\User;

use Symfony\Component\Security\Core\User\UserInterface;

interface UserProviderInterface {

    /**
     * find user given a username
     * @return UserInterface|string|null
     */
    public function getUser($username);

    /**
     * validate user
     * @param UserInterface $user
     * @param string $password
     * @return boolean
     */
    public function isValid(UserInterface $user, $password = '');
}
