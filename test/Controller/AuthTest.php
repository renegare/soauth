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

        $app = $this->createApplication(true);
        $app['soauth.client.provider'] = $this->mockClientProvider;
        $app['soauth.user.provider'] = $this->mockUserProvider;
        $app['soauth.access.provider'] = $this->mockAccessProvider;
        $app['soauth.renderer'] = $this->mockRenderer;
        $this->app = $app;
    }


    public function provideAuthenticateActionTestCases(){
        return [
            # test case 0
            [true, [
                    'client_id' => 1,
                    'redirect_uri' => 'http://external.client.com/redirect/path'
                ], 'test+1@example.com', 'Password123'],
            # test case 1
            [true, [
                    'client_id' => '1',
                    'redirect_uri' => 'http://external.client.com/redirect/path'
                ], 'test+1@example.com', 'Password123'],
            # test case 2
            [false, [
                    'redirect_uri' => 'http://external.client.com/redirect/path'
                ], 'test+1@example.com', 'Password123'],
            # test case 3
            [false, [
                    'client' => 2
                ], 'test+1@example.com', 'Password123'],
            # test case 4
            [false, [
                    'client_id' => '123ss',
                    'redirect_uri' => 'http://external.client.com/redirect/path'
                ], 'test+1@example.com', 'Password123'],
            # test case 5
            [false, [
                    'client_id' => 1,
                    'redirect_uri' => 'kjdskjsdjk23'
                ], 'test+1@example.com', 'Password123'],
            # test case 6
            [false, [], 'test+1@example.com', 'Password123']
        ];
    }

    /**
     * @dataProvider provideAuthenticateActionTestCases
     */
    public function testAuthenticateAction($expectToSucceed, $requestQuery, $expectedUsername, $expectedPassword) {

        $app = $this->app;
        $app['soauth.renderer']->expects($expectToSucceed? $this->once() : $this->never())
            ->method('renderSignInForm')->will($this->returnCallback(function($data) use ($requestQuery){
                $this->assertEquals($requestQuery, $data);

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
        $crawler = $client->request('GET', '/auth/', $requestQuery);

        $response = $client->getResponse();

        if($expectToSucceed) {
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
                'client_id' => $requestQuery['client_id'],
                'redirect_uri' => $requestQuery['redirect_uri']
            ], $form->getPhpValues());
        } else {
            $this->assertFalse($response->isOk());
        }
    }

    public function provideSigninActionTestCases() {
        return [
            [[
                'client_id' => 1,
                'redirect_uri' => 'http://external.client.com/redirect/path',
                'username' => 'test+1@example.com',
                'password' => 'Password123'
            ]],

            [[
                'client_id' => '1sss',
                'redirect_uri' => 'not_a_url',
                'username' => '',
                'password' => '',
                'invalid_field' => 'should be ignored!'
            ], ['client_id', 'redirect_uri', 'username', 'password']],

            [[], ['client_id', 'redirect_uri', 'username', 'password']],

            [[
                'client_id' => '1',
                'redirect_uri' => 'http://external.client.com/redirect/path',
                'username' => 'test+1@example.com',
                'password' => 'Password123'
            ], [], true],

            [[
                'client_id' => '1',
                'redirect_uri' => 'http://external.client.com/redirect/path',
                'username' => 'test+1@example.com',
                'password' => 'Password123'
            ], [], false, true],

            [[
                'client_id' => '1',
                'redirect_uri' => 'http://external.client.com/redirect/path',
                'username' => 'test+1@example.com',
                'password' => 'Password123'
            ], [], false, false, true]
        ];
    }

    /**
     * @dataProvider provideSigninActionTestCases
     */
    public function testSigninAction($requestData, array $expectedValidationError = null, $expectInvalidClient = false, $expectInvalidUser = false, $expectAuthProviderException = false) {

        $expectedIp = '192.168.192.168';

        $expectedToSucceed = !$expectedValidationError && !$expectInvalidClient && !$expectInvalidUser && !$expectAuthProviderException;


        $mockClient = $this->getMock('Renegare\Soauth\ClientInterface');
        $mockUser = $this->getMock('Renegare\Soauth\UserInterface');

        $this->mockClientProvider->expects($this->any())->method('load')
            ->will($this->returnCallback(function($id) use ($mockClient, $requestData, $expectInvalidClient){
                $this->assertEquals($requestData['client_id'], $id);
                if($expectInvalidClient) {
                    throw new \Exception('Some error!');
                }
                return $mockClient;
            }));

        $this->mockUserProvider->expects($this->any())->method('loadByUsername')
            ->will($this->returnCallback(function($username) use ($mockUser, $requestData, $expectInvalidUser){
                $this->assertEquals($requestData['username'], $username);

                if($expectInvalidUser) {
                    throw new \Exception('Some error!');
                }

                $mockUser->expects($this->once())
                    ->method('isValidPassword')->will($this->returnValue(true));

                return $mockUser;
            }));

        $this->mockAccessProvider->expects($this->any())->method('generateAccessCredentials')
            ->will($this->returnCallback(function($client, $user, $ip) use ($expectedIp, $mockClient, $mockUser, $expectAuthProviderException) {
                $this->assertEquals($expectedIp, $ip);
                $this->assertEquals($mockClient, $client);
                $this->assertEquals($mockUser, $user);

                if($expectAuthProviderException) {
                    throw new \Exception('Some error!');
                }

                $mockCredentials = $this->getMock('Renegare\Soauth\CredentialsInterface');
                $mockCredentials->expects($this->any())->method('getAuthCode')
                    ->will($this->returnValue('fake_auth_code='));
                return $mockCredentials;
            }));

        $this->app['soauth.renderer']->expects($expectedToSucceed? $this->never() : $this->once())
            ->method('renderSignInForm')->will($this->returnCallback(function($data) use ($requestData, $expectedValidationError){
                if($expectedValidationError) {
                    $this->assertEquals($expectedValidationError, array_keys($data['errors']));
                    unset($data['errors']);
                }

                $this->assertEquals($requestData, $data);

                return '<form method="post">
    <input type="text" name="username" />
    <input type="password" name="password" />
    <input type="hidden" name="redirect_uri" />
    <input type="hidden" name="client_id" />
    <button type="submit">Sign-in</button>
</form>';
            }));

        $client = $this->createClient(['REMOTE_ADDR' => $expectedIp], $this->app);
        $crawler = $client->request('POST', '/auth/', $requestData);
        $response = $client->getResponse();

        if($expectedToSucceed) {
            $this->assertEquals(Response::HTTP_FOUND, $response->getStatusCode());
            $redirectTargetUrl = $response->getTargetUrl();
            $this->assertEquals($requestData['redirect_uri'] . '?code=fake_auth_code=', $redirectTargetUrl);
        } else {
            $this->assertEquals(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
            $formButton = $crawler->selectButton('Sign-in');
            $this->assertCount(1, $formButton);
        }
    }
}
