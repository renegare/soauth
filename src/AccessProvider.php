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
    public function generate(Request $request, $clientId, $redirecUri, $username, $password = '') {
        $ip = $request->getClientIp();
        $user = $this->getUser($username);
        $client = $this->getClient($clientId);

        if(!$this->userProvider->isValid($user, $password)) {
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
    public function refresh($refreshCode) {}

    protected function getDigest($data) {
        return base64_encode(hash_hmac("sha1", $data, $this->secret));
    }
}
