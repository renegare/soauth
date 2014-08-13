<?php

namespace Renegare\Soauth\Test\Controller;

use Symfony\Component\HttpFoundation\Response;

use Renegare\Soauth\Test\WebTestCase;

class AuthTest extends WebTestCase {

    public function testUserCanAuthenticate() {
        $app = $this->createApplication(true);
        $mockRenderer = $this->getMock('Renegare\Soauth\RendererInterface');
        $app['soauth.renderer'] = $mockRenderer;
        $mockRenderer->expects($this->any())
            ->method('renderSignInForm')->will($this->returnCallback(function($data){
                return 'mudi was here';
            }));

        $expectedRedirectTarget = 'http://external.client.com/redirect/path';
        $client = $this->createClient(['REMOTE_ADDR' => '192.168.192.168'], $app);
        $client->followRedirects(false);
        $crawler = $client->request('GET', 'auth', [
            'redirect_uri' => $expectedRedirectTarget,
            'client_id' => 1
        ]);

        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode(), $content);

        $formButton = $crawler->selectButton('Sign-in');
        $this->assertCount(1, $formButton, $content);
    }
}
