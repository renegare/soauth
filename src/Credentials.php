<?php

namespace Renegare\Soauth;

class Credentials implements CredentialsInterface {

    protected $authCode;
    protected $accessCode;
    protected $refreshCode;
    protected $lifetime;
    protected $username;
    protected $clientId;

    /**
     * @param string $authCode
     * @param string $accessCode
     * @param string $refreshCode
     * @param string $expires
     * @param string $username
     */
    public function __construct($authCode, $accessCode, $refreshCode, $lifetime, $clientId, $username) {
        $this->authCode = $authCode;
        $this->accessCode = $accessCode;
        $this->refreshCode = $refreshCode;
        $this->lifetime = $lifetime;
        $this->clientId = $clientId;
        $this->username = $username;
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

    /**
     * {@inheritdoc}
     */
    public function getUsername() {
        return $this->username;
    }

    /**
     * {@inheritdoc}
     */
    public function getClientId() {
        return $this->clientId;
    }

    /**
     * @return $array
     */
    public function toArray() {
        return get_object_vars($this);
    }
}
