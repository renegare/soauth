<?php

namespace Renegare\Soauth\Access;

class ClientCredentialsAccess extends Access {

    protected $clientId;

    /**
     * @param string $clientId
     * @param string $accessToken
     * @param string $refreshToken
     * @param string $expiresIn
     */
    public function __construct($clientId, $accessToken, $refreshToken, $expiresIn = 86400) {
        parent::__construct($accessToken, $refreshToken, $expiresIn);
        $this->clientId = $clientId;
    }

    /**
     * @return string
     */
    public function getClientId() {
        return $this->clientId;
    }

    /**
     * {@inheritdoc}
     */
    public function toArray() {
        return array_merge(parent::toArray(), ['client_id' => $this->clientId]);
    }
}
