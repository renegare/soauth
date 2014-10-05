<?php

namespace Renegare\Soauth\Test\OAuth\GrantFlow;

use Renegare\Soauth\Test\FlowTestCase;
use Renegare\Soauth\Test\WebtestCase;
use Silex\Application;
use Symfony\Component\HttpFoundation\Response;

class ClientCredentialsTest extends FlowTestCase {

    public function testFlow() {
        $app = $this->createApplication(true);

        $app->get('/client-resource', function() {
            return 'All Good!';
        });

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
        $accessToken = $accessDetails['access_token'];
        $client = $this->createClient(['HTTP_X_Authorization' => 'Bearer ' . $accessToken], $app);
        $client->request('GET', '/client-resource');
        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode());
        $this->assertEquals('All Good!', $response->getContent());
    }
}
