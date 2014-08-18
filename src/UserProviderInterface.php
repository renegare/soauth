<?php

namespace Renegare\Soauth;

use Symfony\Component\Security\Core\User\UserInterface;

interface UserProviderInterface {

    /**
     * find user given a username
     * @return UserInterface|string|null
     */
    public function getUsernameUser($username);

    /**
     * validate user
     * @param UserInterface $user
     * @param string $password
     * @return boolean
     */
    public function isValid(UserInterface $user, $password = '');
}
