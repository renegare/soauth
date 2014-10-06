<?php

namespace Renegare\Soauth;

use Symfony\Component\HttpFoundation\Request;
use Renegare\Soauth\Access\ClientCredentialsAccess;
use Renegare\Soauth\Access\AuthorizationCodeAccess;
use Renegare\Soauth\AccessStorageHandler\AccessStorageHandlerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Renegare\Soauth\Access\Access;

class AccessProvider implements SecurityAccessProviderInterface, LoggerInterface {
    use LoggerTrait;

    protected $secret = 'ch4ng3Th1s!!!';
    protected $defaultLifetime = 3600;
    protected $storage;
    protected $clientProvider;
    protected $userProvider;

    /**
     * dependencies
     * @param StorageHandlerInterface $storage
     * @param ClientProvider $client
     * @param UserProvider $user
     */
    public function __construct(AccessStorageHandlerInterface $storage, ClientProviderInterface $client, UserProviderInterface $user) {
        $this->storage = $storage;
        $this->clientProvider = $client;
        $this->userProvider = $user;
    }

    /**
     * {@inheritdoc}
     */
    public function generateAuthorizationCodeAccess(UserInterface $user, ClientInterface $client) {
        $clientId = $client->getId();
        $username = $user->getUsername();

        $authCode = $this->getDigest(sprintf('ac:ac:%s:%s', $clientId, $username));
        $accessToken = $this->getDigest(sprintf('ac:at:%s:%s', $clientId, $username));
        $refreshToken = $this->getDigest(sprintf('ac:rt:%s:%s', $clientId, $username));

        return new AuthorizationCodeAccess($username, $clientId, $authCode, $accessToken, $refreshToken);
    }

    /**
     * {@inheritdoc}
     */
    public function exchange($authCode, $clientSecret) {
        throw new \RuntimeException('Not Implemented Properly: ' . __METHOD__);
        $credentials = $this->storage->getAuthCodeCredentials($authCode);
        $client = $this->getClient($credentials->getClientId());
        if($client->getSecret() !== $clientSecret) {
            $this->error('Incorrect client secret', [
                'secret' => $clientSecret,
                'client_id' => $client->getId()
            ]);
            throw new SoauthException('Incorrect client secret');
        }

        return $credentials;
    }

    /**
     * {@inheritdoc}
     */
    public function getSecurityToken($accessToken) {
        if(!($credentials = $this->storage->getAccess($accessToken))) {
            throw new SoauthException(sprintf('No credenitials found with access code %s', $accessToken));
        }

        $roles = [];
        if($credentials instanceOf AuthorizationCodeAccess) {
            $user = $this->getUser($credentials->getUsername());
            $roles = $user->getRoles();
        } else if($credentials instanceOf ClientCredentialsAccess) {
            $user = $this->getClient($credentials->getClientId());
        }

        $token = new SecurityToken($credentials, $roles);
        $token->setAuthenticated(true);
        $token->setUser($user);
        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function refreshAccess(Access $access, ClientInterface $client, UserInterface $user = null) {
        if($access instanceOf AuthorizationCodeAccess) {
            $refreshedAccess = $this->generateAuthorizationCodeAccess($user, $client);
        } else if($access instanceOf ClientCredentialsAccess ) {
            throw new \RuntimeException('Hmmm ... needs to be implemented!');
        }

        $refreshedAccess->setPreviousAccess($access);
        return $refreshedAccess;
    }

    /**
     * {@inheritdoc}
     */
    public function generateClientCredentialsAccess(ClientInterface $client) {
        $clientId = $client->getId();
        $accessToken = $this->getDigest(sprintf('cc:at:%s', $clientId));
        $refreshToken = $this->getDigest(sprintf('cc:rt:%s', $clientId));
        return new ClientCredentialsAccess($clientId, $accessToken, $refreshToken);
    }

    /**
     * @todo need to make sure value is as unique as possible
     */
    protected function getDigest($data) {
        $rand = openssl_random_pseudo_bytes(16, $strong);
        return base64_encode(hash_hmac("sha1", $data . bin2hex($rand), $this->secret));
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
}
