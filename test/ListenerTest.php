<?php

namespace Renegare\Soauth\Test;

use Symfony\Component\HttpFoundation\Response;
use Renegare\Soauth\Test\WebTestCase;
use Renegare\Soauth\SoauthException;

class ListenerTest extends WebTestCase {

    protected $app;
    protected $mockAccessProvider;

    public function setUp() {
        $app = $this->createApplication(true);

        $this->mockAccessProvider = $this->getMock('Renegare\Soauth\SecurityAccessProviderInterface');
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

        $this->mockAccessProvider->expects($this->once())->method('getSecurityToken')
            ->will($this->returnCallback(function($accessCode) use ($expectedAccessCode) {
                $this->assertEquals($expectedAccessCode, $accessCode);
                $mockSecurityToken = $this->getMockBuilder('Renegare\Soauth\SecurityToken')
                    ->disableOriginalConstructor()
                    ->getMock()
                    ;
                return $mockSecurityToken;
            }));

        $client = $this->createClient(['HTTP_X_Authorization' => 'Bearer: ' . $expectedAccessCode], $this->app);
        $client->request('GET', '/api');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode(), $content);
        $this->assertEquals('Access Granted', $content);
    }

    public function testAccessDeniedForInvalidAuthorizedUser() {
        $expectedAccessCode = 'fake-access-code=';

        $this->mockAccessProvider->expects($this->once())->method('getSecurityToken')
            ->will($this->returnCallback(function($accessCode) use ($expectedAccessCode) {
                $this->assertEquals($expectedAccessCode, $accessCode);
                throw new SoauthException('Something went wrong');
            }));

        $client = $this->createClient(['HTTP_X_ACCESS_CODE' => $expectedAccessCode], $this->app);

        $client->request('GET', '/api');
        $response = $client->getResponse();
        $content = $response->getContent();
        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode(), $content);
    }
}
