<?php

namespace Renegare\Soauth\Test\AuthorizationProvider;

use Renegare\Soauth\Test\WebtestCase;
use Renegare\Soauth\AuthorizationProvider\BearerAuthorizationProvider;
use Symfony\Component\HttpFoundation\Request;

class BearerAuthorizationProviderTest extends WebtestCase {

    /**
     * @expectedException Renegare\Soauth\Exception\SoauthException
     */
    public function testInvalidAuthorizationHeader() {
        $invalidValue = 'Hmm ...';
        $provider = new BearerAuthorizationProvider;
        $request = new Request;
        $request->headers->set('Authorization', $invalidValue);
        $provider->getAuth($request);
    }
}
