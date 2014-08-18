<?php

namespace Renegare\Soauth\Test\OAuth;

use Renegare\Soauth\Test\FlowTestCase;
use Silex\Application;
use Symfony\Component\HttpFoundation\Response;

class RefreshFlowTest extends FlowTestCase {

    protected $app;
    protected $credentials;
    protected $clientSecret;
    protected $verifyAccessTokenCb;

    public function setUp() {
        $app = $this->createApplication(true);

        // authenticate
        $client = $this->createClient([], $app);
        $client->followRedirects(false);
        $crawler = $client->request('GET', '/auth/', [
            'client_id' => 1,
            'redirect_uri' => 'http://client.com/cb'
        ]);

        $form = $crawler->selectButton('Sign-in')->form([
            'username' => 'test@example.com',
            'password' => 'Password123'
        ]);
        $client->submit($form);
        $response = $client->getResponse();
        $redirectTargetUrl = $response->getTargetUrl();

        // exchange for access code
        $this->clientSecret = 'cl13nt53crt';
        $code = explode('?code=', $redirectTargetUrl)[1];
        $client = $this->createClient(['HTTP_X_CLIENT_SECRET' => $this->clientSecret], $app);
        $client->request('POST', '/auth/access', [], [], [], json_encode(['code' => $code]));
        $response = $client->getResponse();

        $this->credentials = json_decode($response->getContent(), true);
        $this->app = $app;

        $verifyAccessTokenCb = null;
        $this->verifyAccessTokenCb &= $verifyAccessTokenCb;

        $app->get('/verify-access-token', function(Application $app) use (&$verifyAccessTokenCb){
            if($verifyAccessTokenCb) {
                $verifyAccessTokenCb($app);
            }
            return 'Access Granted';
        });
    }

    public function testFlow() {
        // ensure we have access
        $accessCode = $this->credentials['access_code'];

        $client = $this->createClient(['HTTP_X_ACCESS_CODE' => $accessCode], $this->app);
        $client->request('GET', '/verify-access-token');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode(), $content);
        $this->assertEquals('Access Granted', $content);

        // refresh access
        $code = $this->credentials['refresh_code'];
        $client = $this->createClient(['HTTP_X_CLIENT_SECRET' => $this->clientSecret], $this->app);
        $client->request('PUT', '/auth/access', ['refresh_code' => $code]);
        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode());
        $newCredentials = json_decode($response->getContent(), true);

        // ensure previous access code is unauthorized
        $accessCode = $this->credentials['access_code'];
        $client = $this->createClient(['HTTP_X_ACCESS_CODE' => $accessCode], $this->app);
        $client->request('GET', '/verify-access-token');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());

        // ensure new access code is recognised
        $accessCode = $newCredentials['access_code'];
        $client = $this->createClient(['HTTP_X_ACCESS_CODE' => $accessCode], $this->app);
        $client->request('GET', '/verify-access-token');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode(), $content);
        $this->assertEquals('Access Granted', $content);
    }
}
