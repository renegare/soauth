<?php

namespace Renegare\Soauth\Test;

use Renegare\Soauth\Client;

class ClientTest extends WebtestCase {

    public function testGetName() {
        $client = new Client(1, 'mudi', 'domain.com', '2j1jj4jh2!');
        $this->assertEquals('mudi', $client->getName());
    }
}
