<?php

namespace Renegare\Soauth;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class SecurityToken extends AbstractToken {

    protected $client;

    /**
     * @param ClientInterface $client
     * @param array $roles
     */
    public function __construct(ClientInterface $client, array $roles = []) {
        parent::__construct($roles);
        $this->client = $client;
    }

    /**
     * @return ClientInterface
     */
    public function getClient() {
        return $this->client;
    }

    /**
     * presently does nothing
     * {@inheritdoc}
     */
    public function getCredentials() {
        return null;
    }
}
