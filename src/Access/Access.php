<?php

namespace Renegare\Soauth\Access;

class Access {

    protected $accessToken;
    protected $refreshToken;
    protected $expiresIn;

    /**
     * @param string $accessToken
     * @param string $refreshToken
     * @param string $expiresIn
     */
    public function __construct($accessToken, $refreshToken, $expiresIn = 3600) {
        $this->accessToken = $accessToken;
        $this->refreshToken = $refreshToken;
        $this->expiresIn = $expiresIn;
    }

    /**
     * @return string
     */
    public function getAccessToken(){
        return $this->accessToken;
    }

    /**
     * {@inheritdoc}
     */
    public function getRefreshToken(){
        return $this->refreshToken;
    }

    /**
     * @return string
     */
    public function getExpiresIn(){
        return $this->expiresIn;
    }

    /**
     * @return string
     */
    public function toArray() {
        return [
            'access_token' => $this->accessToken,
            'refresh_token' => $this->refreshToken,
            'expires_in' => $this->expiresIn
        ];
    }
}
