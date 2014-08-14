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
        $this->mockAccessProvider = $this->getMock('Renegare\Soauth\AccessProviderInterface');
        $app = $this->createApplication(true);
        $app['soauth.access.provider'] = $this->mockAccessProvider;
        $this->app = $app;
    }


    public function provideExchangeActionTestCases(){
        return [
            ['Valid request', 'fake-auth-code=', [
                'access_code' => '',
                'refresh_code' => '',
                'expires' => '3600'
            ]],

            ['Request made with no code', null, null, ['code']],

            ['Request made with invalid code', '', null, ['code']],

            ['Exception is thrown by accessProvider::getAccessCredentials', 'fake-auth-code=', [
                'access_code' => '',
                'refresh_code' => '',
                'expires' => '3600'
            ], null, true]
        ];
    }

    /**
     * @dataProvider provideExchangeActionTestCases
     */
    public function testExchangeAction($testCaseLabel, $expectedAuthCode, array $expectedAccessCredentials = null, array $expectedValidationError = null, $expectedAccessProviderException = false) {

        $expectedSuccess = !$expectedValidationError && !$expectedAccessProviderException;

        $this->mockAccessProvider->expects($this->any())
            ->method('getAccessCredentials')->will($this->returnCallback(function($authCode) use ($expectedAuthCode, $expectedAccessCredentials, $expectedAccessProviderException, $testCaseLabel){
                $this->assertEquals($expectedAuthCode, $authCode, $testCaseLabel);

                if($expectedAccessProviderException) {
                    throw new \Exception('Some error!');
                }

                $mockCredentials = $this->getMock('Renegare\Soauth\CredentialsInterface');
                $mockCredentials->expects($this->once())->method('getAccessCode')->will($this->returnValue($expectedAccessCredentials['access_code']));
                $mockCredentials->expects($this->once())->method('getRefreshCode')->will($this->returnValue($expectedAccessCredentials['refresh_code']));
                $mockCredentials->expects($this->once())->method('getExpires')->will($this->returnValue($expectedAccessCredentials['expires']));

                return $mockCredentials;
            }));

        $client = $this->createClient([], $this->app);
        $client->followRedirects(false);
        $client->request('POST', 'access', $expectedAuthCode? ['code' => $expectedAuthCode] : []);

        $response = $client->getResponse();
        $responseData = json_decode($response->getContent(), true);

        if($expectedSuccess) {
            $this->assertEquals(Response::HTTP_OK, $response->getStatusCode(), $testCaseLabel);
            $this->assertEquals($expectedAccessCredentials, $responseData, $testCaseLabel);
        } else {
            $this->assertEquals(Response::HTTP_BAD_REQUEST, $response->getStatusCode(), $testCaseLabel);
            if($expectedValidationError) {
                $this->assertEquals($expectedValidationError, array_keys($responseData['errors']), $testCaseLabel);
            }
        }

    }

    public function xprovideRefreshActionTestCases() {
        return [
            []
        ];
    }

    /**
     * @dataProvider provideRefreshActionTestCases
     */
    public function xtestRefreshAction() {
        $client = $this->createClient([], $this->app);
        $client->followRedirects(false);
        $client->request('PUT', 'access', $expectedAuthCode? ['code' => $expectedAuthCode] : []);
    }
}
