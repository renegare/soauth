<?php

namespace Renegare\Soauth\Test\OAuth\GrantFlow;

use Silex\Application;
use Symfony\Component\HttpFoundation\Response;
use Renegare\Soauth\Test\FlowTestCase;
use Renegare\Soauth\SoauthTestCaseTrait;

class RefreshFlowTest extends FlowTestCase {
    use SoauthTestCaseTrait;

    public function testAuhorizationCodeRefreshFlow() {
        $app = $this->getApplication();
        $registeredClient = $app['soauth.client.provider']->getClient(1);
        $app->get('/verify-access-token', function(Application $app) {
            return 'Access Granted';
        });

        $access = $this->createAuthorizationCodeAccess([
            'client_id' => $registeredClient->getId(),
            'client_secret' => $registeredClient->getSecret()
        ]);
        $this->saveAccess($app, $access);

        // refresh access
        $accessToken = $access->getAccessToken();
        $refreshToken = $access->getRefreshToken();
        $client = $this->createClient(['HTTP_Authorization' => 'Bearer ' . $accessToken]);
        $client->request('POST', '/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $registeredClient->getId(),
            'client_secret' => $registeredClient->getSecret()
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

    public function testClientCredentialsRefreshFlow() {
        $app = $this->getApplication();
        $registeredClient = $app['soauth.client.provider']->getClient(1);
        $app->get('/verify-access-token', function(Application $app) {
            return 'Access Granted';
        });

        $access = $this->createClientCredentialsAccess([
            'client_id' => $registeredClient->getId()
        ]);
        $this->saveAccess($app, $access);

        // refresh access
        $accessToken = $access->getAccessToken();
        $refreshToken = $access->getRefreshToken();
        $client = $this->createClient(['HTTP_Authorization' => 'Bearer ' . $accessToken]);
        $client->request('POST', '/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $registeredClient->getId(),
            'client_secret' => $registeredClient->getSecret()
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
