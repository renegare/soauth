<?php

namespace Renegare\Soauth\Test\OAuth\GrantFlow;

use Renegare\Soauth\Test\FlowTestCase;
use Renegare\Soauth\Test\WebtestCase;
use Silex\Application;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Client;

class ClientCredentialsTest extends FlowTestCase {

    public function testFlow() {
        $app = $this->createApplication(true);

        $app['soauth.client.provider.config'] = [
            '1' => [
                'name' => 'Example Client',
                'domain' => 'someclient.com',
                'active' => true,
                'secret' => 'cl13nt53crt'
            ]
        ];

        $app->get('/client-resource', function() use ($app) {
            $user = $app['security']->getToken()->getUser();
            $this->assertInstanceOf('Renegare\Soauth\Client\ClientInterface', $user);
            $this->assertEquals('someclient.com', $user->getDomain());
            return 'All Good!';
        });

        $client = $this->createClient([], $app);
        $client->followRedirects(false);

        $response = $this->requestProtectedResource($client);
        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());

        $client->request('POST', '/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => 1,
            'client_secret' => 'cl13nt53crt'
        ]);
        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode());
        $accessDetails = json_decode($response->getContent(), true);
        $this->assertArrayHasKey('access_token', $accessDetails);

        $accessToken = $accessDetails['access_token'];
        $client = $this->createClient(['HTTP_Authorization' => 'Bearer ' . $accessToken], $app);
        $response = $this->requestProtectedResource($client);
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode());
        $this->assertEquals('All Good!', $response->getContent());
    }

    protected function requestProtectedResource(Client $client) {
        $client->request('GET', '/client-resource');
        return $client->getResponse();
    }
}
