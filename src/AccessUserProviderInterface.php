<?php

namespace Renegare\Soauth;

use Symfony\Component\Security\Core\User\UserInterface;

interface AccessUserProviderInterface {

    /**
     * find user given a username
     * @return UserInterface|string|null
     */
    public function getUsernameUser($username);
}
