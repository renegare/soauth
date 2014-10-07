<?php

namespace Renegare\Soauth\Test\Security;

use Renegare\Soauth\Test\WebtestCase;
use Renegare\Soauth\SoauthTestCaseTrait;
use Symfony\Component\HttpFoundation\Response;

class AccessRuleTest extends WebtestCase {
    use SoauthTestCaseTrait;

    public function setUp() {
        parent::setUp();

        $app = $this->getApplication();

        $app['soauth.user.provider.config'] = [
            'test@example.com' => ['password' => $app['security.encoder.digest']->encodePassword('Password123', ''), 'roles' => ['ROLE_USER'], 'enabled' => true]
        ];

        $app['soauth.client.provider.config'] = [
            '1' => [
                'name' => 'Example Client',
                'domain' => 'client.com',
                'active' => true,
                'secret' => 'cl13nt53crt',
                'roles' => ['ROLE_CLIENT']
            ]
        ];

        $app->get('/client-only', function() {
            return 'Client Access Granted';
        });
        $app->get('/user-only', function() {
            return 'User Access Granted';
        });

        $app['security.access_rules'] = [
            ['^/client-only', 'ROLE_CLIENT'],
            ['^/user-only', 'ROLE_USER']
        ];
    }

    public function testClientAccess() {
        $app = $this->getApplication();

        $registeredClient = $app['soauth.client.provider']->getClient(1);
        $access = $this->createClientCredentialsAccess([
            'client_id' => $registeredClient->getId()
        ]);
        $this->saveAccess($app, $access);

        $accessToken = $access->getAccessToken();
        $client = $this->createClient(['HTTP_Authorization' => 'Bearer ' . $accessToken]);

        $client->request('GET', '/client-only');
        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode());
    }

    /**
     * @expectedException Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException
     */
    public function testClientForbiddenAccess() {
        $app = $this->getApplication();

        $registeredClient = $app['soauth.client.provider']->getClient(1);
        $access = $this->createClientCredentialsAccess([
            'client_id' => $registeredClient->getId()
        ]);
        $this->saveAccess($app, $access);

        $accessToken = $access->getAccessToken();
        $client = $this->createClient(['HTTP_Authorization' => 'Bearer ' . $accessToken]);

        $client->request('GET', '/user-only');
        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_FORBIDDEN, $response->getStatusCode());
    }

    public function testUserAccess() {
        $app = $this->getApplication();

        $registeredClient = $app['soauth.client.provider']->getClient(1);
        $registeredUser = $app['soauth.user.provider']->getUser('test@example.com');

        $access = $this->createAuthorizationCodeAccess([
            'username' => $registeredUser->getUsername(),
            'client_id' => $registeredClient->getId()
        ]);
        $this->saveAccess($app, $access);

        $accessToken = $access->getAccessToken();
        $client = $this->createClient(['HTTP_Authorization' => 'Bearer ' . $accessToken]);

        $client->request('GET', '/user-only');
        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode());
    }

    /**
     * @expectedException Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException
     */
    public function testUserForbiddenAccess() {
        $app = $this->getApplication();

        $registeredClient = $app['soauth.client.provider']->getClient(1);
        $registeredUser = $app['soauth.user.provider']->getUser('test@example.com');

        $access = $this->createAuthorizationCodeAccess([
            'username' => $registeredUser->getUsername(),
            'client_id' => $registeredClient->getId()
        ]);
        $this->saveAccess($app, $access);

        $accessToken = $access->getAccessToken();
        $client = $this->createClient(['HTTP_Authorization' => 'Bearer ' . $accessToken]);

        $client->request('GET', '/client-only');
        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_FORBIDDEN, $response->getStatusCode());
    }
}
