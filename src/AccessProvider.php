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
    public function generate($clientId, $redirecUri, $username, $password, Request $request) {
        $ip = $request->getClientIp();
        $accessCode = $this->getDigest(sprintf('auc:%s:%s:%s:%s', $clientId, $username, time(), $ip));
        $authCode = $this->getDigest(sprintf('ac:%s:%s:%s:%s', $clientId, $username, time(), $ip));
        $refreshCode = $this->getDigest(sprintf('rc:%s:%s:%s:%s', $clientId, $username, time(), $ip));
        
        return new Credentials($accessCode, $authCode, $refreshCode, $this->defaultLifetime);
    }

    /**
     * {@inheritdoc}
     */
    public function exchange($authCode) {}

    /**
     * {@inheritdoc}
     */
    public function getAccessToken($accessCode) {}

    /**
     * {@inheritdoc}
     */
    public function refresh($refreshCode) {}

    protected function getDigest($data) {
        return base64_encode(hash_hmac("sha1", $data, $this->secret));
    }
}
