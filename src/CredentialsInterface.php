<?php

namespace Renegare\Soauth;

interface CredentialsInterface {

    /**
     * get auth code
     * @return string
     */
    public function getAuthCode();
}
