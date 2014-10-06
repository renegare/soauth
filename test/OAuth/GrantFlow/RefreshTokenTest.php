<?php

namespace Renegare\Soauth\Test\OAuth\GrantFlow;

use Renegare\Soauth\Test\FlowTestCase;
use Silex\Application;
use Symfony\Component\HttpFoundation\Response;

class RefreshFlowTest extends FlowTestCase {

    protected $app;
    protected $access;
    protected $client;
    protected $verifyAccessTokenCb;

    public function setUp() {
        parent::setUp();

        $app = $this->getApplication();

        $client = $app['soauth.client.provider']->getClient(1);
        $user = $app['soauth.user.provider']->getUser('test@example.com');
        $access = $app['soauth.access.provider']->generateAuthorizationCodeAccess($user, $client);
        $app['soauth.storage.handler']->save($access);

        $this->access = $access;
        $this->client = $client;

        $app->get('/verify-access-token', function(Application $app) use (&$verifyAccessTokenCb){
            if($verifyAccessTokenCb) {
                $verifyAccessTokenCb($app);
            }
            return 'Access Granted';
        });
    }

    public function testFlow() {
        // ensure we have access
        $accessToken = $this->access->getAccessToken();

        // refresh access
        $refreshToken = $this->access->getRefreshToken();
        $client = $this->createClient(['HTTP_Authorization' => 'Bearer ' . $accessToken]);
        $client->request('POST', '/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->client->getId(),
            'client_secret' => $this->client->getSecret()
        ]);

        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode());
        $newAccess = json_decode($response->getContent(), true);
        $this->assertArrayHasKey('access_token', $newAccess);
        $this->assertArrayHasKey('refresh_token', $newAccess);
        $this->assertArrayHasKey('expires_in', $newAccess);
        $this->assertNotEquals($accessToken, $newAccess['access_token']);

        // ensure previous access code is unauthorized
        $client = $this->createClient(['HTTP_Authorization' => 'Bearer ' . $accessToken]);
        $client->request('GET', '/verify-access-token');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());

        // ensure new access code is recognised
        $accessToken = $newAccess['access_token'];
        $client = $this->createClient(['HTTP_Authorization' => 'Bearer ' . $accessToken]);
        $client->request('GET', '/verify-access-token');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode(), $content);
        $this->assertEquals('Access Granted', $content);
    }
}
