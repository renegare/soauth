<?php

namespace Renegare\Soauth\Test;

use Silex\Application;
use Symfony\Component\HttpFoundation\Response;

class OAuthFlowConcreteTest extends WebtestCase {
    protected $mockRenderer;

    protected function configureApplication(Application $app) {
        parent::configureApplication($app);

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
    }

    public function testRefresh() {
        $this->markTestIncomplete();
    }

    public function testRequest() {
        $this->markTestIncomplete();
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
