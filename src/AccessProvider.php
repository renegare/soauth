<?php

namespace Renegare\Soauth;

use Symfony\Component\HttpFoundation\Request;

class AccessProvider implements AccessProviderInterface, LoggerInterface {
    use LoggerTrait;

    /** @var AccessStorageHandlerInterface */
    protected $storage;
    /** @var AccessClientProvider */
    protected $client;
    /** @var AccessUserProvider */
    protected $user;

    public function __construct(AccessStorageHandlerInterface $storage, AccessClientProvider $client, AccessUserProvider $user) {
        $this->storage = $storage;
        $this->client = $client;
        $this->user = $user;
    }

    /**
     * {@inheritdoc}
     */
    public function generate($clientId, $redirecUri, $username, $password, Request $request) {}

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
}
