<?php

namespace Renegare\Soauth\Test;

use Renegare\Soauth\AccessProvider;
use Renegare\Soauth\MockStorageHandler;

class AccessProviderTest extends WebtestCase {

    /**
     * @expectedException Renegare\Soauth\SoauthException
     */
    public function testGenerateNullClientException() {
        $mockStorage = new MockStorageHandler;
        $mockClientProvider = $this->getMock('Renegare\Soauth\ClientProviderInterface');
        $mockUserProvider = $this->getMock('Renegare\Soauth\UserProviderInterface');
        $mockRequest = $this->getMock('Symfony\Component\HttpFoundation\Request');

        $mockUserProvider->expects($this->any())->method('getUser')->will($this->returnValue($this->getMock('Symfony\Component\Security\Core\User\UserInterface')));
        $mockUserProvider->expects($this->any())->method('isValid')->will($this->returnValue(true));

        $mockClientProvider->expects($this->once())
            ->method('getClient')->will($this->returnCallback(function($id) {
                $this->assertEquals(1, $id);
                return null;
            }));
        $accessProvider = new AccessProvider($mockStorage, $mockClientProvider, $mockUserProvider);
        $accessProvider->generate($mockRequest, 1, '...', 'user...');
    }


    /**
     * @expectedException Renegare\Soauth\SoauthException
     */
    public function testGenerateInvalidClientException() {
        $mockStorage = new MockStorageHandler;
        $mockClientProvider = $this->getMock('Renegare\Soauth\ClientProviderInterface');
        $mockUserProvider = $this->getMock('Renegare\Soauth\UserProviderInterface');
        $mockRequest = $this->getMock('Symfony\Component\HttpFoundation\Request');

        $mockUserProvider->expects($this->any())->method('getUser')->will($this->returnValue($this->getMock('Symfony\Component\Security\Core\User\UserInterface')));
        $mockUserProvider->expects($this->any())->method('isValid')->will($this->returnValue(true));
        $mockClient = $this->getMock('Renegare\Soauth\ClientInterface');

        $mockClientProvider->expects($this->once())
            ->method('getClient')->will($this->returnCallback(function($id) use ($mockClient) {
                $this->assertEquals(1, $id);
                return $mockClient;
            }));
        $mockClientProvider->expects($this->once())
            ->method('isValid')->will($this->returnCallback(function($client) use ($mockClient) {
                $this->assertSame($mockClient, $client);
                return false;
            }));
        $accessProvider = new AccessProvider($mockStorage, $mockClientProvider, $mockUserProvider);
        $accessProvider->generate($mockRequest, 1, '...', 'user...');
    }
}
