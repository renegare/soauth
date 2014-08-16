<?php

namespace Renegare\Soauth\Test\OAuth;

use Renegare\Soauth\Test\WebtestCase;
use Silex\Application;
use Symfony\Component\HttpFoundation\Response;

class GrantFlowTest extends WebtestCase {
    protected $mockRenderer;

    protected function configureApplication(Application $app) {
        parent::configureApplication($app);

        $app['soauth.access.user.provider.config'] = [
            'test@example.com' => ['password' => $app['security.encoder.digest']->encodePassword('Password123', ''), 'roles' => ['ROLE_USER'], 'enabled' => true]
        ];

        $app['soauth.access.client.provider.config'] = [
            '1' => ['name' => 'Example Client']
        ];

        $this->configureMocks($app);
    }

    public function provideTestAuthenticateDatasets() {
        return [
            [true, 1, 'http://client.com/cb', 'test@example.com', 'Password123']
        ];
    }
    /**
     * @dataProvider provideTestAuthenticateDatasets
     */
    public function testAuthenticate($expectToSucceed, $clientId, $redirectUri, $username, $password) {
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
        $formButton = $crawler->selectButton('Sign-in');
        $this->assertCount(1, $formButton, $response->getContent());
        $form = $formButton->form([
            'username' => 'test@example.com',
            'password' => 'Password123'
        ]);
        $client->submit($form);
        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_FOUND, $response->getStatusCode());
        $redirectTargetUrl = $response->getTargetUrl();
        $this->assertContains('http://client.com/cb' . '?code', $redirectTargetUrl);

        // server flow (exchange for access code)
        $code = explode('?code=', $redirectTargetUrl)[1];
        $client = $this->createClient([], $app);
        $client->request('POST', '/auth/access', ['code' => $code]);
        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode());
        $credentials = json_decode($response->getContent(), true);

        // set test to verify security access token and X-ACCESS-CODE header on client
        $accessCode = $credentials['access_code'];
        $verifyAccessTokenCb = function(Application $app) use ($accessCode){
            $token = $app['security']->getToken();
            $credentials = $token->getCredentials();
            $this->assertEquals($accessCode, $credentials->getAccessCode());
            $this->assertEquals('test@example.com', $token->getUsername());
            $this->assertEquals('1', $token->getClient()->getId());
        };

        $client = $this->createClient(['HTTP_X_ACCESS_CODE' => $accessCode], $app);
        $client->request('GET', '/verify-access-token');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode(), $content);
        $this->assertEquals('Access Granted', $content);
    }

    protected function configureMocks(Application $app) {
        $this->mockRenderer = $this->getMock('Renegare\Soauth\RendererInterface');
        $app['soauth.renderer'] = $this->mockRenderer;
        $this->mockRenderer->expects($this->any())
            ->method('renderSignInForm')->will($this->returnCallback(function($data) {
                return '<form method="post">
    <input type="text" name="username" value="'. (isset($data['username'])? $data['username'] : '') .'"/>
    <input type="password" name="password" />
    <input type="hidden" name="redirect_uri" value="'. $data['redirect_uri'] .'" />
    <input type="hidden" name="client_id" value="'. $data['client_id'] .'" />
    <button type="submit">Sign-in</button>
</form>';
            }));
    }
}
