<?php

namespace Renegare\Soauth\Test;

use Renegare\Soauth\Test\FlowTestCase;
use Renegare\Soauth\SoauthTestCaseTrait;
use Silex\Application;
use Symfony\Component\HttpFoundation\Response;

class TestCaseTraitTest extends FlowTestCase {
    use SoauthTestCaseTrait;


    public function testCreateCredentials() {
        $credentials = $this->createCredentials();

        $this->assertEquals([
            'accessCode' => 'valid-test-access-code=',
            'authCode' => 'valid-test-auth-code=',
            'clientId' => 1,
            'lifetime' => 3600,
            'refreshCode' => 'valid-test-refresh-code=',
            'username' => 'test@example.com',
        ], $credentials->toArray());
    }

    public function testCreateCredentialsWithOverrides() {
        $credentials = $this->createCredentials([
            'accessCode' => 'override-test-access-code=',
            'authCode' => 'override-test-auth-code=',
            'clientId' => 2,
            'lifetime' => 7200,
            'refreshCode' => 'override-test-refresh-code=',
            'username' => 'override@example.com',
            'extra.params' => 'have no effect!'
        ]);

        $this->assertEquals([
            'accessCode' => 'override-test-access-code=',
            'authCode' => 'override-test-auth-code=',
            'clientId' => 2,
            'lifetime' => 7200,
            'refreshCode' => 'override-test-refresh-code=',
            'username' => 'override@example.com'
        ], $credentials->toArray());
    }

    public function testStoreCredentials() {
        $app = $this->createApplication();

        // using the storage handler
        $credentials = $this->createCredentials();
        $mockStorage = $this->getMock('Renegare\Soauth\StorageHandlerInterface');
        $mockStorage->expects($this->once())->method('save')
            ->with($this->equalTo($credentials), $this->equalTo(null));
        $app['soauth.test'] = false;
        $app['soauth.storage.handler'] = $mockStorage;
        $this->saveCredentials($credentials, null, $app);

        // using mock
        $time = strtotime('-1 hour');
        $credentials = $this->createCredentials();
        $mockStorage = $this->getMock('Renegare\Soauth\StorageHandlerInterface');
        $mockStorage->expects($this->once())->method('save')
            ->with($this->equalTo($credentials), $this->equalTo($time));
        $app['soauth.test'] = true;
        $app['soauth.storage.handler.mock'] = $mockStorage;
        $this->saveCredentials($credentials, $time, $app);
    }
}
