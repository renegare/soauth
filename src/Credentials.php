<?php

namespace Renegare\Soauth;

class Credentials implements CredentialsInterface {

    protected $authCode;
    protected $accessCode;
    protected $refreshCode;
    protected $lifetime;

    /**
     * @param string $authCode
     * @param string $accessCode
     * @param string $refreshCode
     * @param string $expires
     */
    public function __construct($authCode, $accessCode, $refreshCode, $lifetime) {
        $this->authCode = $authCode;
        $this->accessCode = $accessCode;
        $this->refreshCode = $refreshCode;
        $this->lifetime = $lifetime;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthCode() {
        return $this->authCode;
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessCode(){
        return $this->accessCode;
    }

    /**
     * {@inheritdoc}
     */
    public function getRefreshCode(){
        return $this->refreshCode;
    }

    /**
     * {@inheritdoc}
     */
    public function getLifetime(){
        return $this->lifetime;
    }
}
