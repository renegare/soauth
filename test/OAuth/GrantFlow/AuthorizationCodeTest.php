<?php

namespace Renegare\Soauth\Test\OAuth\GrantFlow;

use Renegare\Soauth\Test\FlowTestCase;
use Renegare\Soauth\Test\WebtestCase;
use Silex\Application;
use Symfony\Component\HttpFoundation\Response;

class AuthorizationCodeTest extends FlowTestCase {

    public function testFlow() {
        $clientId = 1;
        $redirectUri = 'http://client.com/cb';
        $username = 'test@example.com';
        $password = 'Password123';
        $clientSecret = 'cl13nt53crt';

        $app = $this->getApplication();

        $app->get('/verify-access-token', function(Application $app) {
            return 'Access Granted';
        });

        // ensure initial resource access is rejected
        $client = $this->createClient([]);
        $client->request('GET', '/verify-access-token');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode(), $content);

        // user flow
        $client = $this->createClient([], $app);
        $client->followRedirects(false);
        $crawler = $client->request('GET', '/oauth/auth', [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri
        ]);
        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode());

        $formButton = $crawler->selectButton('Sign-in');
        $this->assertCount(1, $formButton, $response->getContent());
        $form = $formButton->form([
            'username' => $username,
            'password' => $password
        ]);
        $client->submit($form);
        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_FOUND, $response->getStatusCode());

        $redirectTargetUrl = $response->getTargetUrl();
        $this->assertContains('http://client.com/cb' . '?code', $redirectTargetUrl);

        // server flow (exchange for access code)
        $code = explode('?code=', $redirectTargetUrl)[1];

        $client = $this->createClient([], $app);

        $client->request('POST', '/oauth/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'client_id' => $clientId,
            'client_secret' => $clientSecret
        ]);

        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode());

        // set test to verify security access token and X-ACCESS-CODE header on client
        $credentials = json_decode($response->getContent(), true);
        $accessCode = $credentials['access_token'];

        $client = $this->createClient(['HTTP_Authorization' => 'Bearer ' . $accessCode], $app);
        $client->request('GET', '/verify-access-token');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode(), $content);
        $this->assertEquals('Access Granted', $content);

        $token = $app['security']->getToken();
        $this->assertTrue($token->isAuthenticated());
        $this->assertEquals($username, $token->getUsername());
        $access = $token->getCredentials();
        $this->assertInstanceOf('Renegare\Soauth\Access\AuthorizationCodeAccess', $access);
        $this->assertEquals($clientId, $access->getClientId());
        $roles = $token->getRoles();
        $this->assertCount(1, $roles);
        $this->assertEquals('ROLE_USER', $roles[0]->getRole());
    }
}
