<?php

namespace Renegare\Soauth;

use Silex\Application;

trait SoauthTestCaseTrait {

    public function createCredentials(array $overrides = []) {
        $attr = array_merge([
            'accessCode' => 'valid-test-access-code=',
            'authCode' => 'valid-test-auth-code=',
            'clientId' => 1,
            'lifetime' => 3600,
            'refreshCode' => 'valid-test-refresh-code=',
            'username' => 'test@example.com'
        ], $overrides);

        extract($attr);

        return new Credentials($authCode, $accessCode, $refreshCode, $lifetime, $clientId, $username);
    }

    public function saveCredentials(CredentialsInterface $credentials, $createdTime = null, Application $app) {
        if($app['soauth.test']) {
            $storage = $app['soauth.storage.handler.mock'];
        } else {
            $storage = $app['soauth.storage.handler'];
        }

        return $storage->save($credentials, $createdTime);
    }
}
