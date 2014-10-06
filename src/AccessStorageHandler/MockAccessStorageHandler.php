<?php

namespace Renegare\Soauth\AccessStorageHandler;

use Renegare\Soauth\Access\Access;
use Renegare\Soauth\Access\AuthorizationCodeAccess;
use Renegare\Soauth\Access\ClientCredentialsAccess;

class MockAccessStorageHandler implements AccessStorageHandlerInterface {

    protected $credentialStore = [];

    /**
     * {@inheritdoc}
     */
    public function save(Access $access, $createdTime = null) {
        $this->credentialStore[] = [$access, $createdTime? $createdTime : time()];
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationCodeAccess($authCode) {
        return $this->findCredentials(function($record) use ($authCode){
            list($credentials, $created) = $record;

            return $credentials instanceOf AuthorizationCodeAccess && $credentials->getAuthCode() === $authCode && ($created + $credentials->getExpiresIn()) > time();
        });
    }

    /**
     * {@inheritdoc}
     */
    public function getAccess($accessToken) {
        return $this->findCredentials(function($record) use ($accessToken){
            list($credentials, $created) = $record;

            return $credentials->getAccessToken() === $accessToken && ($created + $credentials->getExpiresIn()) > time();
        });
    }

    /**
     * {@inheritdoc}
     */
    public function invalidate(Access $access) {
        foreach($this->credentialStore as $index => $record) {
            if($record[0]->getAccessToken() === $access->getAccessToken()) {
                array_splice($this->credentialStore, 0, 1);
                break;
            }
        }
    }

    protected function findCredentials(\Closure $callback) {
        $matches = array_filter($this->credentialStore, $callback);
        $credentials = null;
        if(count($matches) > 0) {
            $credentials = array_shift($matches)[0];
        }
        return $credentials;
    }
}
