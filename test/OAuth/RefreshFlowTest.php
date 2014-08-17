<?php

namespace Renegare\Soauth\Test\OAuth;

use Renegare\Soauth\Test\FlowTestCase;
use Silex\Application;
use Symfony\Component\HttpFoundation\Response;

class RefreshFlowTest extends FlowTestCase {

    protected $app;
    protected $credentials;

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
        $code = explode('?code=', $redirectTargetUrl)[1];
        $client = $this->createClient([], $app);
        $client->request('POST', '/auth/access', ['code' => $code]);
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
        $accessCode = $this->credentials['access_code'];
        $client = $this->createClient(['HTTP_X_ACCESS_CODE' => $accessCode], $this->app);
        $client->request('GET', '/verify-access-token');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode(), $content);
        $this->assertEquals('Access Granted', $content);

        $code = $this->credentials['refresh_code'];
        $client = $this->createClient([], $this->app);
        $client->request('PUT', '/auth/access', ['refresh_code' => $code]);
        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode());

        $accessCode = $this->credentials['access_code'];
        $client = $this->createClient(['HTTP_X_ACCESS_CODE' => $accessCode], $this->app);
        $client->request('GET', '/verify-access-token');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
    }
}
