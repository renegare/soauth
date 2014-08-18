<?php

namespace Renegare\Soauth;

use Symfony\Component\HttpFoundation\Request;

interface SecurityAccessProviderInterface extends AccessProviderInterface {

    /**
     * get security access token (that contains credentials) for the given access code
     * @param $accessCode string
     * @return AccessToken
     */
    public function getSecurityToken($accessCode);
}
