<?php

namespace Renegare\Soauth\Test\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;

use Renegare\Soauth\Test\WebTestCase;
use Renegare\Soauth\SoauthException;

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
        $this->mockAccessProvider = $this->getMock('Renegare\Soauth\SecurityAccessProviderInterface');
        $app = $this->createApplication(true);
        $app['soauth.access.provider'] = $this->mockAccessProvider;
        $this->app = $app;
    }


    public function provideExchangeActionTestCases(){
        return [
            ['Valid request', 'fake-auth-code=', 'cl13nt53cr3t!', [
                'access_code' => 'fake-access-code=',
                'refresh_code' => 'fake-refresh-code=',
                'lifetime' => '3600'
            ]],

            ['Request made with no code', null, 'cl13nt53cr3t!', null, ['code']],

            ['Request made with invalid code', '', 'cl13nt53cr3t!', null, ['code']],

            ['Exception is thrown by accessProvider::exchange', 'fake-auth-code=', 'cl13nt53cr3t!', null, null, true]
        ];
    }

    /**
     * @dataProvider provideExchangeActionTestCases
     */
    public function testExchangeAction($testCaseLabel, $expectedAuthCode, $expectedClientSecret, array $expectedAccessCredentials = null, array $expectedValidationError = null, $expectedAccessProviderException = false) {

        $expectedSuccess = !$expectedValidationError && !$expectedAccessProviderException;

        $this->mockAccessProvider->expects($this->any())
            ->method('exchange')->will($this->returnCallback(function($authCode, $clientSecret) use ($expectedAuthCode, $expectedAccessCredentials, $expectedAccessProviderException, $testCaseLabel, $expectedClientSecret){
                $this->assertEquals($expectedClientSecret, $clientSecret);
                $this->assertEquals($expectedAuthCode, $authCode, $testCaseLabel);

                if($expectedAccessProviderException) {
                    throw new SoauthException('Some error!');
                }

                $mockCredentials = $this->getMock('Renegare\Soauth\CredentialsInterface');
                $mockCredentials->expects($this->once())->method('getAccessCode')->will($this->returnValue($expectedAccessCredentials['access_code']));
                $mockCredentials->expects($this->once())->method('getRefreshCode')->will($this->returnValue($expectedAccessCredentials['refresh_code']));
                $mockCredentials->expects($this->once())->method('getLifetime')->will($this->returnValue($expectedAccessCredentials['lifetime']));

                return $mockCredentials;
            }));

        $client = $this->createClient(['HTTP_X_CLIENT_SECRET' => $expectedClientSecret], $this->app);
        $client->followRedirects(false);
        $client->request('POST', '/auth/access/', [], [], [], $expectedAuthCode? json_encode(['code' => $expectedAuthCode]) : null);

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

    public function provideRefreshActionTestCases() {
        return [
            ['Valid Request', 'fake-refresh-code=', 'cl13nt53cr3t!', [
                'access_code' => 'new-fake-access-code=',
                'refresh_code' => 'new-fake-refresh-code=',
                'lifetime' => '3600'
            ]],

            ['Invalid Request #1', '', 'cl13nt53cr3t!', null, ['refresh_code']],
            ['Invalid Request #2', null, 'cl13nt53cr3t!', null, ['refresh_code']],

            ['Exception is thrown by accessProvider::exchange', 'fake-refresh-code=', 'cl13nt53cr3t!', null, null, true]
        ];
    }

    /**
     * @dataProvider provideRefreshActionTestCases
     */
    public function testRefreshAction($testCaseLabel, $expectedRefreshCode, $expectedClientSecret, $expectedAccessCredentials = null, array $expectedValidationError = null, $expectedAccessProviderException = false) {

        $expectedSuccess = !$expectedValidationError && !$expectedAccessProviderException;

        $this->mockAccessProvider->expects($expectedValidationError? $this->never() : $this->once())
            ->method('refresh')->will($this->returnCallback(function(Request $request, $refreshCode, $clientSecret) use ($expectedClientSecret, $expectedRefreshCode, $expectedAccessCredentials, $testCaseLabel, $expectedAccessProviderException){
                $this->assertEquals($expectedRefreshCode, $refreshCode, $testCaseLabel);
                $this->assertEquals($expectedClientSecret, $clientSecret);

                if($expectedAccessProviderException) {
                    throw new SoauthException('Some error!');
                }

                $mockCredentials = $this->getMock('Renegare\Soauth\CredentialsInterface');
                $mockCredentials->expects($this->once())->method('getAccessCode')->will($this->returnValue($expectedAccessCredentials['access_code']));
                $mockCredentials->expects($this->once())->method('getRefreshCode')->will($this->returnValue($expectedAccessCredentials['refresh_code']));
                $mockCredentials->expects($this->once())->method('getLifetime')->will($this->returnValue($expectedAccessCredentials['lifetime']));

                return $mockCredentials;
            }));

        $client = $this->createClient(['HTTP_X_CLIENT_SECRET' => $expectedClientSecret], $this->app);
        $client->followRedirects(false);
        $client->request('PUT', '/auth/access/', $expectedRefreshCode? ['refresh_code' => $expectedRefreshCode] : []);

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
}
