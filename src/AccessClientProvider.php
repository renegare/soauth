<?php

namespace Renegare\Soauth;

class AccessClientProvider implements AccessClientProviderInterface {

    protected $clientStore;

    public function __construct(array $clientStore = []) {
        $this->clientStore = $clientStore;
    }

    /**
     * {@inheritdoc}
     */
    public function getClient($id) {
        foreach($this->clientStore as $clientId => $client) {
            if((integer) $clientId === (integer) $id) {
                return new Client($clientId, $client['name'], $client['domain'], $client['active']);
            }
        }
    }

    public function isValid(ClientInterface $client, $redirectUri) {
        $pattern = sprintf('/^https?:\\/\\/.*%s(?:\\/.*)?$/', preg_replace('/\./', '\\.', $client->getDomain()));
        return $client->isActive() && preg_match($pattern, $redirectUri);
    }
}
