<?php

namespace Renegare\Soauth\Test\Client;

use Renegare\Soauth\Client\Client;
use Renegare\Soauth\Test\WebtestCase;

class ClientTest extends WebtestCase {

    public function testMisc() {
        $client = new Client(1, 'mudi', 'domain.com', '2j1jj4jh2!');
        $this->assertEquals('mudi', $client->getName());
        $this->assertEquals(1, $client->getUsername());
        $this->assertEquals([], $client->getRoles());
        $this->assertEquals('2j1jj4jh2!', $client->getPassword());
        $this->assertNull($client->getSalt());

        $client->eraseCredentials();
        $this->assertNull($client->getPassword());
    }
}
