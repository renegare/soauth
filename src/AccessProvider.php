<?php

namespace Renegare\Soauth;

use Symfony\Component\HttpFoundation\Request;
use Renegare\Soauth\Access\ClientCredentialsAccess;
use Renegare\Soauth\Access\AuthorizationCodeAccess;
use Renegare\Soauth\AccessStorageHandler\AccessStorageHandlerInterface;

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
    public function generateAuthorizationCodeAccess(Request $request, $clientId, $redirectUri, $username, $password = '') {
        $ip = $request->getClientIp();
        $user = $this->getUser($username);
        $client = $this->getClient($clientId);

        if(!$this->userProvider->isValid($user, $password)) {
            throw new SoauthException(sprintf('Bad user: %s', $username));
        }

        if(!$this->clientProvider->isValid($client, $redirectUri)) {
            throw new SoauthException(sprintf('Bad user: %s', $username));
        }

        $this->debug('found valid user and client', ['user' => $username, 'client' => $clientId]);

        $accessCode = $this->getDigest(sprintf('auc:%s:%s:%s:%s', $clientId, $username, time(), $ip));
        $authCode = $this->getDigest(sprintf('ac:%s:%s:%s:%s', $clientId, $username, time(), $ip));
        $refreshCode = $this->getDigest(sprintf('rc:%s:%s:%s:%s', $clientId, $username, time(), $ip));

        $credentials = new Credentials($accessCode, $authCode, $refreshCode, $this->defaultLifetime, $clientId, $username);
        $this->storage->save($credentials);

        return $credentials;
    }

    /**
     * {@inheritdoc}
     */
    public function exchange($authCode, $clientSecret) {
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
    public function getSecurityToken($accessCode) {
        if(!($credentials = $this->storage->getAccessTokenCredentials($accessCode))) {
            throw new SoauthException(sprintf('No credenitials found with access code %s', $accessCode));
        }

        /*
        if($credentials instanceOf AuthorizationCodeAccess) {
            $user = $this->getUser($credentials->getUsername());
        }

        if($credentials instanceOf ClientCredentialsAccess) {
            $client = $this->getClient($credentials->getClientId());
        }
        */

        $token = new SecurityToken($credentials);
        $token->setAuthenticated(true);
        // $token->setUser($user);
        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function refresh(Request $request, $refreshCode) {
        $credentials = $this->storage->getRefreshCodeCredentials($refreshCode);

        $ip = $request->getClientIp();
        $username = $credentials->getUsername();
        $clientId = $credentials->getClientId();
        $user = $this->getUser($username);
        $client = $this->getClient($clientId);

        $this->debug('found valid user and client', ['user' => $username, 'client' => $clientId]);

        $accessCode = $this->getDigest(sprintf('auc:%s:%s:%s:%s', $clientId, $username, $refreshCode, $ip));
        $authCode = $this->getDigest(sprintf('ac:%s:%s:%s:%s', $clientId, $username, $refreshCode, $ip));
        $refreshCode = $this->getDigest(sprintf('rc:%s:%s:%s:%s', $clientId, $username, $refreshCode, $ip));
        $newCredentials = new Credentials($accessCode, $authCode, $refreshCode, $this->defaultLifetime, $clientId, $username);

        $this->debug('refreshed credentials', ['old_access_code' => $credentials->getAccessCode(), 'new_access_code' => $newCredentials->getAccessCode()]);
        $this->storage->save($newCredentials);
        $this->storage->invalidate($credentials);

        return $newCredentials;
    }

    /**
     * {@inheritdoc}
     */
    public function generateClientCredentialsAccess(ClientInterface $client) {
        $clientId = $client->getId();
        $accessCode = $this->getDigest(sprintf('auc:%s', $clientId));
        $refreshCode = $this->getDigest(sprintf('rc:%s', $clientId));
        return new ClientCredentialsAccess($clientId, $accessCode, $refreshCode);
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
