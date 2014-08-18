<?php

namespace Renegare\Soauth\Test\OAuth;

use Renegare\Soauth\Test\FlowTestCase;
use Renegare\Soauth\Test\WebtestCase;
use Silex\Application;
use Symfony\Component\HttpFoundation\Response;

class GrantFlowTest extends FlowTestCase {

    public function provideTestFlowDatasets() {
        return [
            [true, 1, 'http://client.com/cb', 'test@example.com', 'Password123', 'cl13nt53crt'],
            [false, 1, 'http://client.com/cb', 'incorrect@example.com', 'Password123', 'cl13nt53crt'],
            [false, 1, 'http://client.com/cb', 'test@example.com', 'IncorrectPassword123', 'cl13nt53crt'],
            [false, 2, 'http://client.com/cb', 'test@example.com', 'Password123', 'cl13nt53crt'],
            [false, 3, 'http://client.com/cb', 'test@example.com', 'Password123', 'cl13nt53crt'],
            [false, 1, 'http://not.same.domain.com/cb', 'test@example.com', 'Password123', 'cl13nt53crt'],
            [false, 1, 'http://client.com/cb', 'test@example.com', 'Password123', 'Inc0rr3ct!cl13nt53crt'],
            [false, 1, 'http://client.com/cb', 'test@example.com', 'Password123']
        ];
    }
    /**
     * @dataProvider provideTestFlowDatasets
     */
    public function testFlow($expectToSucceed, $clientId, $redirectUri, $username, $password, $clientSecret = null) {
        $app = $this->createApplication(true);

        $verifyAccessTokenCb = null;
        $app->get('/verify-access-token', function(Application $app) use (&$verifyAccessTokenCb){
            $verifyAccessTokenCb($app);

            return 'Access Granted';
        });

        // ensure initial resource access is rejected
        $client = $this->createClient([], $app);
        $client->request('GET', '/verify-access-token');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode(), $content);

        // user flow
        $client = $this->createClient([], $app);
        $client->followRedirects(false);
        $crawler = $client->request('GET', '/auth/', [
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri
        ]);
        $response = $client->getResponse();

        if($response->getStatusCode() !== Response::HTTP_OK) {
            $this->assertFalse($expectToSucceed);
            $this->assertEquals(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
            return;
        }

        $formButton = $crawler->selectButton('Sign-in');
        $this->assertCount(1, $formButton, $response->getContent());
        $form = $formButton->form([
            'username' => $username,
            'password' => $password
        ]);
        $client->submit($form);
        $response = $client->getResponse();

        if($response->getStatusCode() !== Response::HTTP_FOUND) {
            $this->assertFalse($expectToSucceed);
            $this->assertEquals(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
            return;
        }

        $redirectTargetUrl = $response->getTargetUrl();
        $this->assertContains('http://client.com/cb' . '?code', $redirectTargetUrl);

        // server flow (exchange for access code)
        $code = explode('?code=', $redirectTargetUrl)[1];
        if($clientSecret) {
            $client = $this->createClient(['HTTP_X_CLIENT_SECRET' => $clientSecret], $app);
        } else {
            $client = $this->createClient([], $app);
        }
        $client->request('POST', '/auth/access', ['code' => $code]);
        $response = $client->getResponse();

        if($response->getStatusCode() !== Response::HTTP_OK) {
            $this->assertFalse($expectToSucceed);
            $this->assertEquals(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
            return;
        }

        // set test to verify security access token and X-ACCESS-CODE header on client
        $credentials = json_decode($response->getContent(), true);
        $accessCode = $credentials['access_code'];
        $verifyAccessTokenCb = function(Application $app) use ($accessCode, $username, $clientId){
            $token = $app['security']->getToken();
            $this->assertEquals($username, $token->getUsername());
            $this->assertEquals($clientId, $token->getClient()->getId());
        };

        $client = $this->createClient(['HTTP_X_ACCESS_CODE' => $accessCode], $app);
        $client->request('GET', '/verify-access-token');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode(), $content);
        $this->assertEquals('Access Granted', $content);
        $this->assertTrue($expectToSucceed);
    }
}
