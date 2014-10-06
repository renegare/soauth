<?php

namespace Renegare\Soauth\AuthorizationProvider;

use Renegare\Soauth\SoauthException;
use Symfony\Component\HttpFoundation\Request;

interface AuthorizationProviderInterface {

    /**
     * return authorization identifier
     * @param Request $request
     * @return mixed
     * @throws SoauthException
     */
    public function getAuth(Request $request);
}
