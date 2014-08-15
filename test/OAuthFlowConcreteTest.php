<?php

namespace Renegare\Soauth\Test;

use Silex\Application;

class OAuthFlowConcreteTest extends WebtestCase {
    protected $mockRenderer;

    protected function configureApplication(Application $app) {
        parent::configureApplication($app);

        $this->configureMocks($app);
    }

    protected function configureMocks(Application $app) {
        $this->mockRenderer = $this->getMock('Renegare\Soauth\RendererInterface');
        $app['soauth.renderer'] = $this->mockRenderer;
        $this->mockRenderer->expects($this->any())
            ->method('renderSignInForm')->will($this->returnCallback(function($data) {
                return '<form method="post">
    <input type="text" name="username" value="'. (isset($data['username'])? $data['username'] : $data['username']) .'"/>
    <input type="password" name="password" />
    <input type="hidden" name="redirect_uri" value="'. $data['redirect_uri'] .'" />
    <input type="hidden" name="client_id" value="'. $data['client_id'] .'" />
    <button type="submit">Sign-in</button>
</form>';
            }));
    }

    public function testAuthenticate() {
        $app = $this->createApplication();
        $client = $this->createClient([], $app);
        $client->followRedirects(false);
        $crawler = $client->request('GET', '/auth/', [
            'client_id' => '1',
            'redirect_id' => 'http://client.com/cb'
        ]);

        $response = $client->getResponse();
        $formButton = $crawler->selectButton('Sign-in');
        $this->assertCount(1, $formButton, $response->getContent());
    }

    public function testRefresh() {
        $this->markTestIncomplete();
    }

    public function testRequest() {
        $this->markTestIncomplete();
    }
}
