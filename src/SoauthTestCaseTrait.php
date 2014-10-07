<?php

namespace Renegare\Soauth;

use Silex\Application;
use Renegare\Soauth\Access\Access;
use Renegare\Soauth\Access\AuthorizationCodeAccess;
use Renegare\Soauth\Access\ClientCredentialsAccess;

trait SoauthTestCaseTrait {

    public function createAuthorizationCodeAccess(array $overrides = []) {
        $attr = array_merge([
            'username' => 'test@example.com',
            'client_id' => 1,
            'auth_code' => 'valid-test-auth-code=',
            'access_token' => 'valid-test-access-code=',
            'refresh_token' => 'valid-test-refresh-code=',
            'expires_in' => 3600
        ], $overrides);

        extract($attr);

        return new AuthorizationCodeAccess($username, $client_id, $auth_code, $access_token, $refresh_token, $expires_in);
    }

    public function createClientCredentialsAccess(array $overrides = []) {
        $attr = array_merge([
            'client_id' => 1,
            'access_token' => 'valid-test-access-code=',
            'refresh_token' => 'valid-test-refresh-code=',
            'expires_in' => 3600
        ], $overrides);

        extract($attr);

        return new ClientCredentialsAccess($client_id, $access_token, $refresh_token, $expires_in);
    }

    public function saveAccess(Application $app, Access $access, $createdTime = null) {
        return $app['soauth.storage.handler']->save($access, $createdTime);
    }
}
