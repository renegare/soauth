<?php

namespace Renegare\Soauth;

class MockAccessStorageHandler implements AccessStorageHandlerInterface {

    protected $credentialStore = [];

    /**
     * {@inheritdoc}
     */
    public function save(CredentialsInterface $credentials) {
        $this->credentialStore[] = [$credentials, time()];
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthCodeCredentials($authCode) {
        return $this->findCredentials(function($record) use ($authCode){
            list($credentials, $created) = $record;

            return $credentials->getAuthCode() === $authCode && ($created + $credentials->getLifeTime()) > time();
        });
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessCodeCredentials($accessCode) {
        return $this->findCredentials(function($record) use ($accessCode){
            list($credentials, $created) = $record;

            return $credentials->getAccessCode() === $accessCode && ($created + $credentials->getLifeTime()) > time();
        });
    }

    protected function findCredentials(\Closure $callback) {
        $matches = array_filter($this->credentialStore, $callback);

        return count($matches) > 0 ? $matches[0][0] : null;
    }
}
