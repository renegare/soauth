<?php

namespace Renegare\Soauth\Test\Controller;

use Symfony\Component\HttpFoundation\Response;

use Renegare\Soauth\Test\WebTestCase;

class AccessTest extends WebTestCase {

    protected $mockClientProvider;
    protected $mockUserProvider;
    protected $mockAccessProvider;
    protected $mockRenderer;
    protected $app;

    /**
     * mock out all dependencies ... cause we can!
     */
    public function setUp() {
        // $this->mockClientProvider = $this->getMock('Renegare\Soauth\ClientProviderInterface');
        // $this->mockUserProvider = $this->getMock('Renegare\Soauth\UserProviderInterface');
        // $this->mockAccessProvider = $this->getMock('Renegare\Soauth\AccessProviderInterface');
        // $this->mockRenderer = $this->getMock('Renegare\Soauth\RendererInterface');

        $app = $this->createApplication(true);
        // $app['soauth.client.provider'] = $this->mockClientProvider;
        // $app['soauth.user.provider'] = $this->mockUserProvider;
        // $app['soauth.access.provider'] = $this->mockAccessProvider;
        // $app['soauth.renderer'] = $this->mockRenderer;
        $this->app = $app;
    }


    public function provideExchangeActionTestCases(){
        return [
            []
        ];
    }

    /**
     * @dataProvider provideExchangeActionTestCases
     */
    public function testExchangeAction() {
        $requestQuery = [
            'code' => 'fake-auth-code='
        ];

        $client = $this->createClient([], $this->app);
        $client->followRedirects(false);
        $client->request('GET', 'access', $requestQuery);

        $response = $client->getResponse();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode());

    }
}
