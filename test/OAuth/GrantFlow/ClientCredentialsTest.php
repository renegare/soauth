<?php

namespace Renegare\Soauth\Test\OAuth\GrantFlow;

use Renegare\Soauth\Test\FlowTestCase;
use Renegare\Soauth\Test\WebtestCase;
use Silex\Application;
use Symfony\Component\HttpFoundation\Response;

class ClientCredentialsTest extends FlowTestCase {

    public function testFlow() {
        $app = $this->createApplication(true);

        // $app['soauth.access.provider'] = $mockAccessProvider;

        $client = $this->createClient([], $app);
        $client->followRedirects(false);

        $client->request('POST', '/auth/', [
            'grant_type' => 'client_credentials',
            'client_id' => 1,
            'client_secret' => 'cl13nt53crt'
        ]);

        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode());
        $accessDetails = json_decode($response->getContent(), true);
        $this->assertArrayHasKey('access_token', $accessDetails);
    }
}
