<?php

namespace Renegare\Soauth\AuthorizationProvider;

use Renegare\Soauth\Exception\SoauthException;
use Symfony\Component\HttpFoundation\Request;

class BearerAuthorizationProvider implements AuthorizationProviderInterface {

    /**
     * {@inheritdoc}
     */
    public function getAuth(Request $request) {
        $headers = $request->headers;
        if(!$headers->has('Authorization')) {
            throw new SoauthException('Authorization header not present in request');
        }

        if(!preg_match('/^Bearer (.+)$/', $headers->get('Authorization'), $matches)) {
            throw new SoauthException('Authorization value malformed');
        }

        return $matches[1];
    }
}
