<?php

namespace Renegare\Soauth\Test\Security;

use Renegare\Soauth\Test\WebTestCase;

class ListenerTest extends WebTestCase {

    public function setUp() {
        $app['security.firewalls'] = [
            'api' => [
                'pattern' => "^/"
            ]
        ];
    }

    public function testSomething() {
        $this->assertTrue(true);
    }
}
