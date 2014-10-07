<?php

namespace Renegare\Soauth\SecurityToken;

use Symfony\Component\HttpFoundation\Request;

interface SecurityTokenProviderInterface {

    /**
     * get security token
     * @param Request $request
     * @return SecurityToken
     */
    public function getSecurityToken(Request $request);
}
