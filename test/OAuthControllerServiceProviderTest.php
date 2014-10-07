<?php

namespace Renegare\Soauth\Test;

use Renegare\Soauth\Test\WebtestCase;

class OAuthControllerServiceProviderTest extends WebtestCase {

    /**
     * @expectedException Renegare\Soauth\Exception\SoauthException
     */
    public function testUnconfiguredSoauthStorageHandlerService() {
        $app = $this->getApplication();
        $app['soauth.test'] = false; // diable test mode
        $handler = $app['soauth.storage.handler'];
    }
}
