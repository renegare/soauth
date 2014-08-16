<?php

namespace Renegare\Soauth;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class AccessToken extends AbstractToken {

    /** @var CredentialsInterface */
    protected $credentials;
    protected $client;

    public function __construct(CredentialsInterface $credentials, array $roles = []) {
        parent::__construct($roles);
        $this->credentials = $credentials;
    }

    public function getCredentials() {
        return $this->credentials;
    }

    public function eraseCredentials() {
        parent::eraseCredentials();
        $this->credentials = null;
    }

    /**
     * @return ClientInterface
     */
    public function getClient() {
        return $this->client;
    }

    /**
     * set client
     * @param ClientInterface $client
     */
    public function setClient(ClientInterface $client) {
        $this->client = $client;
    }
}
