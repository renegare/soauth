<?php

namespace Renegare\Soauth\Test;

use Symfony\Component\HttpFoundation\Response;
use Renegare\Soauth\Test\WebTestCase;

class ListenerTest extends WebTestCase {

    protected $app;
    protected $mockAccessProvider;

    public function setUp() {
        $app = $this->createApplication(true);

        $app->register(new \Silex\Provider\SecurityServiceProvider);

        $app['security.firewalls'] = [
            'healthcheck' => [
                'pattern' => '^/healthcheck',
                'anonymous' => true,
                'stateless' => true
            ],

            'auth' => [
                'pattern' => '^/auth',
                'anonymous' => true,
                'stateless' => true
            ],

            'api' => [
                'pattern' => '^/',
                'soauth' => true,
                'stateless' => true
            ]
        ];

        $app->get('/healthcheck', function(){
            return 'All Good!';
        });

        $app->get('/api', function(){
            return 'Access Granted';
        });

        $this->mockAccessProvider = $this->getMock('Renegare\Soauth\AccessProviderInterface');
        $app['soauth.access.provider'] = $this->mockAccessProvider;
        $this->app = $app;
    }

    public function testCanAccessHealthcheck() {
        $client = $this->createClient([], $this->app);
        $client->request('GET', '/healthcheck');
        $this->assertEquals('All Good!', $client->getResponse()->getContent());
    }

    public function testAccessDeniedForAnonymousUser() {
        $client = $this->createClient([], $this->app);

        $client->request('GET', '/api');
        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
    }

    public function testAccessAllowedForAuthorizedUser() {
        $expectedAccessCode = 'fake-access-code=';

        $this->mockAccessProvider->expects($this->once())->method('getAccessToken')
            ->will($this->returnCallback(function($accessCode) use ($expectedAccessCode) {
                $this->assertEquals($expectedAccessCode, $accessCode);
                return $this->getMockBuilder('Renegare\Soauth\AccessToken')
                    ->disableOriginalConstructor()
                    ->getMock()
                    ;
            }));

        $client = $this->createClient(['HTTP_X_ACCESS_CODE' => $expectedAccessCode], $this->app);

        $client->request('GET', '/api');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode(), $content);
        $this->assertEquals('Access Granted', $content);
    }

    public function testAccessDeniedForInvalidAuthorizedUser() {
        $expectedAccessCode = 'fake-access-code=';

        $this->mockAccessProvider->expects($this->once())->method('getAccessToken')
            ->will($this->returnCallback(function($accessCode) use ($expectedAccessCode) {
                $this->assertEquals($expectedAccessCode, $accessCode);
                throw new \Exception('Something went wrong');
            }));

        $client = $this->createClient(['HTTP_X_ACCESS_CODE' => $expectedAccessCode], $this->app);

        $client->request('GET', '/api');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode(), $content);
    }
}
