<?php

namespace Renegare\Soauth;

use Symfony\Component\HttpFoundation\Request;

class AccessProvider implements AccessProviderInterface, LoggerInterface {
    use LoggerTrait;

    protected $secret = 'ch4ng3Th1s!!!';
    protected $defaultLifetime = 3600;
    protected $storage;
    protected $clientProvider;
    protected $userProvider;

    /**
     * dependencies
     * @param AccessStorageHandlerInterface $storage
     * @param AccessClientProvider $client
     * @param AccessUserProvider $user
     */
    public function __construct(AccessStorageHandlerInterface $storage, AccessClientProvider $client, AccessUserProvider $user) {
        $this->storage = $storage;
        $this->clientProvider = $client;
        $this->userProvider = $user;
    }

    /**
     * {@inheritdoc}
     */
    public function generate(Request $request, $clientId, $redirectUri, $username, $password = '') {
        $ip = $request->getClientIp();
        $user = $this->getUser($username);
        $client = $this->getClient($clientId);

        if(!$this->userProvider->isValid($user, $password)) {
            throw new SoauthException(sprintf('Bad user: %s', $username));
        }

        if(!$this->clientProvider->isValid($client, $redirectUri)) {
            throw new SoauthException(sprintf('Bad user: %s', $username));
        }

        $this->info('found valid user and client', ['user' => $username, 'client' => $clientId]);

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
    public function exchange($authCode) {
        return $this->storage->getAuthCodeCredentials($authCode);
    }

    protected function getUser($username) {
        if(!($user = $this->userProvider->getUsernameUser($username))) {
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

    /**
     * {@inheritdoc}
     */
    public function getAccessToken($accessCode) {
        if(!($credentials = $this->storage->getAccessCodeCredentials($accessCode))) {
            throw new SoauthException(sprintf('No credenitials found with access code %s', $accessCode));
        }

        $user = $this->getUser($credentials->getUsername());
        $client = $this->getClient($credentials->getClientId());

        $token = new AccessToken($credentials, []);
        $token->setUser($user);
        $token->setClient($client);
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

        $this->info('found valid user and client', ['user' => $username, 'client' => $clientId]);

        $accessCode = $this->getDigest(sprintf('auc:%s:%s:%s:%s', $clientId, $username, $refreshCode, $ip));
        $authCode = $this->getDigest(sprintf('ac:%s:%s:%s:%s', $clientId, $username, $refreshCode, $ip));
        $refreshCode = $this->getDigest(sprintf('rc:%s:%s:%s:%s', $clientId, $username, $refreshCode, $ip));
        $newCredentials = new Credentials($accessCode, $authCode, $refreshCode, $this->defaultLifetime, $clientId, $username);

        $this->info('refreshed credentials', ['new_access_code' => $credentials->getAccessCode(), 'old_access_code' => $newCredentials->getAccessCode()]);
        $this->storage->save($newCredentials);
        $this->storage->invalidate($credentials);

        return $credentials;
    }

    protected function getDigest($data) {
        return base64_encode(hash_hmac("sha1", $data . rand(0,1000), $this->secret));
    }
}
