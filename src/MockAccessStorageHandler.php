<?php

namespace Renegare\Soauth;

class MockAccessStorageHandler implements AccessStorageHandlerInterface {

    protected $credentialStore = [];

    /**
     * {@inheritdoc}
     */
    public function getAuthCodeCredentials($authCode) {
        $matches = array_filter($this->credentialStore, function($record) use ($authCode){
            list($credentials, $created) = $record;

            return $credentials->getAuthCode() === $authCode && ($created + $credentials->getLifeTime()) > time();
        });

        return count($matches) > 0 ? $matches[0][0] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function save(CredentialsInterface $credentials) {
        $this->credentialStore[] = [$credentials, time()];
    }
}
