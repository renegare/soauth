<?php

namespace Renegare\Soauth\Controller;

use Symfony\Component\Validator\Validation;
use Symfony\Component\Validator\Constraints\Collection;
use Renegare\Soauth\SoauthException;
use Renegare\Soauth\BadDataException;
use Renegare\Soauth\LoggerInterface;
use Renegare\Soauth\LoggerTrait;
use Renegare\Soauth\ClientProviderInterface;
use Renegare\Soauth\UserProviderInterface;

abstract class AbstractController implements LoggerInterface {
    use LoggerTrait;

    protected $userProvider;
    protected $clientProvider;

    public function setUserProvider(UserProviderInterface $provider) {
        $this->userProvider = $provider;
    }

    public function setClientProvider(ClientProviderInterface $provider) {
        $this->clientProvider = $provider;
    }

    protected function getUser($username) {
        if(!($user = $this->userProvider->getUser($username))) {
            throw new SoauthException(sprintf('No user found with username %s', $username));
        }
        return $user;
    }

    protected function getClient($clientId) {
        if(!($client = $this->clientProvider->getClient($clientId))) {
            throw new SoauthException(sprintf('No client found with id %s', $clientId));
        }
        return $client;
    }

    protected function getValidClient($id, $secret) {
        $client = $this->getClient($id);
        if(!$client || $secret !== $client->getSecret() || !$client->isActive()) {
            throw new SoauthException('Invalid client, client id: ' . $id);
        }

        return $client;
    }
}
