<?php

namespace Renegare\Soauth\Test;

use Silex\Application;
use Symfony\Component\HttpFoundation\Response;
use Renegare\Soauth\Enum\GrantType;
use Renegare\Soauth\Access\AuthorizationCodeAccess;

class TokenControllerTest extends WebtestCase {

    /**
     * @expectedException Renegare\Soauth\Exception\SoauthException
     */
    public function testUnsupportedGrantType() {
        $client = $this->createClient();
        $client->request('POST', '/oauth/token', [
            'grant_type' => 'unsupported_flow',
            'code' => 'some-code=',
            'client_id' => 1,
            'client_secret' => '53cr3t!'
        ]);
    }

    public function provideTestAuthorizationCodeInvalidClientData() {
        return [
            [[
                'code' => 'some-code=',
                'client_id' => 3,
                'client_secret' => 'cl13nt53crt'], 'Non existent client'],
            [[
                'code' => 'some-code=',
                'client_id' => 1,
                'client_secret' => 'wrongSecrect', 'Incorrect client secret']],
            [[
                'code' => 'some-code=',
                'client_id' => 2,
                'client_secret' => 'cl13nt53crt', 'Inactive client']],
            [[
                'code' => 'some-code=',
                'client_id' => 1,
                'client_secret' => 'cl13nt53crt', 'Non existent authcode']],
            [[
                'code' => 'client-2-auth-code=',
                'client_id' => 1,
                'client_secret' => 'cl13nt53crt', 'Incorrect client id auth_code']]
        ];
    }
    /**
     * @dataProvider provideTestAuthorizationCodeInvalidClientData
     * @expectedException Renegare\Soauth\Exception\SoauthException
     */
    public function testAuthorizationCodeInvalidRequestData($requestData) {
        $app = $this->getApplication();
        $access = new AuthorizationCodeAccess('...', 2, 'client-2-auth-code=', '...', '...');
        $app['soauth.storage.handler']->save($access);

        $app['soauth.client.provider.config'] = [
            '1' => [
                'name' => 'Example Client',
                'domain' => 'client.com',
                'active' => true,
                'secret' => 'cl13nt53crt'
            ],
            '2' => [
                'name' => 'Example Client',
                'domain' => 'client.com',
                'active' => false,
                'secret' => 'cl13nt53crt'
            ]
        ];
        $requestData['grant_type'] = GrantType::AUTHORIZATION_CODE;
        $client = $this->createClient();
        $client->request('POST', '/oauth/token', $requestData);
    }

    /**
     * @expectedException Renegare\Soauth\Exception\SoauthException
     */
    public function testRefreshCodeMismatch() {
        $app = $this->getApplication();
        $access1 = new AuthorizationCodeAccess('...', 1, 'auth-code=', '...', 'refresh-code=');
        $access2 = new AuthorizationCodeAccess('...', 1, 'auth-code=', '...', '...');
        $app['soauth.storage.handler']->save($access1);
        $app['soauth.storage.handler']->save($access2);

        $app['soauth.client.provider.config'] = [
            '1' => [
                'name' => 'Example Client',
                'domain' => 'client.com',
                'active' => true,
                'secret' => 'cl13nt53crt'
            ]
        ];

        $client = $this->createClient(['HTTP_Authorization' => 'Bearer ' . $access1->getAccessToken()]);
        $client->request('POST', '/oauth/token', [
            'grant_type' => GrantType::REFRESH_TOKEN,
            'refresh_token' => $access2->getRefreshToken(),
            'client_id' => 1,
            'client_secret' => 'cl13nt53crt'
        ]);
    }

    /**
     * @expectedException Renegare\Soauth\Exception\SoauthException
     */
    public function testRefreshCodeInvalidUser() {
        $app = $this->getApplication();
        $access1 = new AuthorizationCodeAccess('...', 1, 'auth-code=', '...', 'refresh-code=');
        $app['soauth.storage.handler']->save($access1);

        $app['soauth.client.provider.config'] = [
            '1' => [
                'name' => 'Example Client',
                'domain' => 'client.com',
                'active' => true,
                'secret' => 'cl13nt53crt'
            ]
        ];

        $client = $this->createClient(['HTTP_Authorization' => 'Bearer ' . $access1->getAccessToken()]);
        $client->request('POST', '/oauth/token', [
            'grant_type' => GrantType::REFRESH_TOKEN,
            'refresh_token' => $access1->getRefreshToken(),
            'client_id' => 1,
            'client_secret' => 'cl13nt53crt'
        ]);
    }
}
