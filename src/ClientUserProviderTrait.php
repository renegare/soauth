<?php

namespace Renegare\Soauth;

trait ClientUserProviderTrait {
    protected $userProvider;
    protected $clientProvider;

    public function setUserProvider(UserProviderInterface $provider) {
        $this->userProvider = $provider;
    }

    public function setClientProvider(ClientProviderInterface $provider) {
        $this->clientProvider = $provider;
    }

    /**
     * @param string username
     * @return UserInterface
     * @throws SoauthException
     */
    protected function getUser($username) {
        if(!($user = $this->userProvider->getUser($username))) {
            throw new SoauthException(sprintf('No user found with username %s', $username));
        }
        return $user;
    }

    /**
     * @param string id
     * @return ClientInterface
     * @throws SoauthException
     */
    protected function getClient($id) {
        if(!($client = $this->clientProvider->getClient($id))) {
            throw new SoauthException(sprintf('No client found with id %s', $id));
        }
        return $client;
    }

    /**
     * @param string id
     * @param string secret
     * @return ClientInterface
     * @throws SoauthException
     */
    protected function getValidClient($id, $secret) {
        $client = $this->getClient($id);
        if(!$client || $secret !== $client->getSecret() || !$client->isActive()) {
            throw new SoauthException('Invalid client, client id: ' . $id);
        }

        return $client;
    }
}
