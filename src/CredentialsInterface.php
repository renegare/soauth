<?php

namespace Renegare\Soauth;

interface CredentialsInterface {

    /**
     * get auth code
     * @return string
     */
    public function getAuthCode();

    /**
     * get auth code
     * @return string
     */
    public function getAccessCode();

    /**
     * get refresh code
     * @return string
     */
    public function getRefreshCode();

    /**
     * get expires
     * @return string|integer
     */
    public function getExpires();
}
