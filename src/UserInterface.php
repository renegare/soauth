<?php

namespace Renegare\Soauth;

interface UserInterface {
    /**
     * verify given $password matches the stored password of the user
     * @param $password string
     * @return boolean
     */
    public function isValidPassword($password);
}
