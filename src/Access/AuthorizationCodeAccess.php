<?php

namespace Renegare\Soauth\Access;

class AuthorizationCodeAccess extends ClientCredentialsAccess {

    protected $username;
    protected $authCode;

    /**
     * @param string $username
     * @param string $clientId
     * @param string $authCode;
     * @param string $accessToken
     * @param string $refreshToken
     * @param string $expiresIn
     */
    public function __construct($username, $clientId, $authCode, $accessToken, $refreshToken, $expiresIn = 3600) {
        parent::__construct($clientId, $accessToken, $refreshToken, $expiresIn);
        $this->username = $username;
        $this->authCode = $authCode;
    }

    /**
     * @return string
     */
    public function getUsername() {
        return $this->username;
    }

    /**
     * @return string
     */
    public function getAuthCode() {
        return $this->authCode;
    }

    /**
     * {@inheritdoc}
     */
    public function toArray() {
        return array_merge(parent::toArray(), [
            'username' => $this->username,
            'auth_code' => $this->authCode
        ]);
    }
}
