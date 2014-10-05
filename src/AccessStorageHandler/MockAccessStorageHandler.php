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
    public function save(Access $credentials, $createdTime = null) {
        $this->credentialStore[] = [$credentials, $createdTime? $createdTime : time()];
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthCodeCredentials($authCode) {
        return $this->findCredentials(function($record) use ($authCode){
            list($credentials, $created) = $record;

            return $credentials instanceOf AuthorizationCodeAccess && $credentials->getAuthCode() === $authCode && ($created + $credentials->getExpiresIn()) > time();
        });
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenCredentials($accessCode) {
        return $this->findCredentials(function($record) use ($accessCode){
            list($credentials, $created) = $record;

            return $credentials->getAccessToken() === $accessCode && ($created + $credentials->getExpiresIn()) > time();
        });
    }

    /**
     * {@inheritdoc}
     */
    public function getRefreshTokenCredentials($refreshCode) {
        return $this->findCredentials(function($record) use ($refreshCode){
            list($credentials, $created) = $record;

            return $credentials->getRefreshToken() === $refreshCode && ($created + $credentials->getExpiresIn()) > time();
        });
    }

    /**
     * {@inheritdoc}
     */
    public function invalidate(Access $credentials) {
        foreach($this->credentialStore as $index => $record) {
            if($record[0]->getAccessCode() === $credentials->getAccessCode()) {
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
