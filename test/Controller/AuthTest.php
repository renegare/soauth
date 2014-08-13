<?php

namespace Renegare\Soauth\Test\Controller;

use Symfony\Component\HttpFoundation\Response;

use Renegare\Soauth\Test\WebTestCase;

class AuthTest extends WebTestCase {

    public function testUserCanAuthenticate() {
        $expectedClientId = 1;
        $expectedRedirectTarget = 'http://external.client.com/redirect/path';

        $app = $this->createApplication(true);
        $mockRenderer = $this->getMock('Renegare\Soauth\RendererInterface');
        $app['soauth.renderer'] = $mockRenderer;
        $mockRenderer->expects($this->any())
            ->method('renderSignInForm')->will($this->returnCallback(function($data) use ($expectedClientId, $expectedRedirectTarget){
                $this->assertEquals([
                    'redirect_uri' => $expectedRedirectTarget,
                    'client_id' => $expectedClientId
                ], $data);

                return '<form method="post">
    <input type="text" name="username" />
    <input type="password" name="password" />
    <input type="hidden" name="redirect_uri" value="'. $data['redirect_uri'] .'" />
    <input type="hidden" name="client_id" value="'. $data['client_id'] .'" />
    <button type="submit">Sign-in</button>
</form>';
            }));

        $mockClientProvider = $this->getMock('Renegare\Soauth\ClientProviderInterface');
        $app['soauth.client.provider'] = $mockClientProvider;
        $mockClientProvider->expects($this->any())->method('load')
            ->will($this->returnCallback(function($id){
                $this->assertEquals(1, $id);
                $mockClient = $this->getMock('Renegare\Soauth\ClientInterface');
                return $mockClient;
            }));

        $mockUserProvider = $this->getMock('Renegare\Soauth\UserProviderInterface');
        $app['soauth.user.provider'] = $mockUserProvider;
        $mockUserProvider->expects($this->any())->method('loadByUsername')
            ->will($this->returnCallback(function($username){
                $this->assertEquals('test+1@example.com', $username);
                $mockUser = $this->getMock('Renegare\Soauth\UserInterface');
                return $mockUser;
            }));

        $mockAccessProvider = $this->getMock('Renegare\Soauth\AccessProviderInterface');
        $app['soauth.access.provider'] = $mockAccessProvider;
        $mockAccessProvider->expects($this->any())->method('generateAccessCredentials')
            ->will($this->returnCallback(function($client, $user, $ip){
                $this->assertEquals('192.168.192.168', $ip);

                $mockCredentials = $this->getMock('Renegare\Soauth\CredentialsInterface');
                $mockCredentials->expects($this->any())->method('getAuthCode')
                    ->will($this->returnValue('fake_auth_code='));
                return $mockCredentials;
            }));

        $client = $this->createClient(['REMOTE_ADDR' => '192.168.192.168'], $app);
        $client->followRedirects(false);
        $crawler = $client->request('GET', 'auth', [
            'client_id' => $expectedClientId,
            'redirect_uri' => $expectedRedirectTarget
        ]);

        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode(), $content);

        $formButton = $crawler->selectButton('Sign-in');
        $this->assertCount(1, $formButton, $content);

        $form = $formButton->form([
            'username' => 'test+1@example.com',
            'password' => 'Password123'
        ]);

        $client->submit($form);
        $response = $client->getResponse();
        $this->assertEquals(302, $response->getStatusCode());
        $redirectTargetUrl = $response->getTargetUrl();
        $this->assertEquals($expectedRedirectTarget . '?code=fake_auth_code=', $redirectTargetUrl);
    }
}
