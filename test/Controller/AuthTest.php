<?php

namespace Renegare\Soauth\Test\Controller;

use Symfony\Component\HttpFoundation\Response;

use Renegare\Soauth\Test\WebTestCase;

class AuthTest extends WebTestCase {

    protected $mockClientProvider;
    protected $mockUserProvider;
    protected $mockAccessProvider;
    protected $mockRenderer;
    protected $app;

    /**
     * mock out all dependencies ... cause we can!
     */
    public function setUp() {
        $this->mockClientProvider = $this->getMock('Renegare\Soauth\ClientProviderInterface');
        $this->mockUserProvider = $this->getMock('Renegare\Soauth\UserProviderInterface');
        $this->mockAccessProvider = $this->getMock('Renegare\Soauth\AccessProviderInterface');
        $this->mockRenderer = $this->getMock('Renegare\Soauth\RendererInterface');

        // $this->mockClient = $this->getMock('Renegare\Soauth\ClientInterface');
        // $this->mockUser = $this->getMock('Renegare\Soauth\UserInterface');

        $app = $this->createApplication(true);
        $app['soauth.client.provider'] = $this->mockClientProvider;
        $app['soauth.user.provider'] = $this->mockUserProvider;
        $app['soauth.access.provider'] = $this->mockAccessProvider;
        $app['soauth.renderer'] = $this->mockRenderer;
        $this->app = $app;
    }

    public function testAuthenticateAction() {
        $expectedClientId = 1;
        $expectedRedirectTarget = 'http://external.client.com/redirect/path';
        $expectedUsername = 'test+1@example.com';
        $expectedPassword = 'Password123';

        $app = $this->app;
        $app['soauth.renderer']->expects($this->once())
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

        $client = $this->createClient([], $app);
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
            'username' => $expectedUsername,
            'password' => $expectedPassword
        ]);

        $this->assertEquals([
            'username' => $expectedUsername,
            'password' => $expectedPassword,
            'client_id' => $expectedClientId,
            'redirect_uri' => $expectedRedirectTarget
        ], $form->getPhpValues());
    }

    public function xtestSigninAction() {
        $this->markTestIncomplete();

        $mockClient = $this->getMock('Renegare\Soauth\ClientInterface');
        $mockUser = $this->getMock('Renegare\Soauth\UserInterface');

        $mockClientProvider = $this->getMock('Renegare\Soauth\ClientProviderInterface');

        $mockClientProvider->expects($this->any())->method('load')
            ->will($this->returnCallback(function($id) use ($mockClient){
                $this->assertEquals(1, $id);
                return $mockClient;
            }));



        $mockUserProvider->expects($this->any())->method('loadByUsername')
            ->will($this->returnCallback(function($username) use ($mockUser){
                $this->assertEquals('test+1@example.com', $username);

                $mockUser->expects($this->once())
                    ->method('isValidPassword')->will($this->returnValue(true));

                return $mockUser;
            }));



        $mockAccessProvider->expects($this->any())->method('generateAccessCredentials')
            ->will($this->returnCallback(function($client, $user, $ip) use ($mockClient, $mockUser) {
                $this->assertEquals('192.168.192.168', $ip);
                $this->assertEquals($mockClient, $client);
                $this->assertEquals($mockUser, $user);
                $mockCredentials = $this->getMock('Renegare\Soauth\CredentialsInterface');
                $mockCredentials->expects($this->any())->method('getAuthCode')
                    ->will($this->returnValue('fake_auth_code='));
                return $mockCredentials;
            }));

        /*
        $client->submit($form);
        $response = $client->getResponse();
        $this->assertEquals(302, $response->getStatusCode());
        $redirectTargetUrl = $response->getTargetUrl();
        $this->assertEquals($expectedRedirectTarget . '?code=fake_auth_code=', $redirectTargetUrl);
        */
    }
}
