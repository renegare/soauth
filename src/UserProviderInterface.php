<?php

namespace Renegare\Soauth;

interface UserProviderInterface {

    /**
     * load a user with a given username
     * @param $username string
     * @return UserInterface
     */
    public function loadByUsername($username);
}
