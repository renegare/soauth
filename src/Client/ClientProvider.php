<?php

namespace Renegare\Soauth\Client;

class ClientProvider implements ClientProviderInterface {

    protected $clientStore;

    /**
     * @param array $clientStore - list of clients
     * e.g (were the array key is the id of the client)
     * [
     *     '1' => [
     *         'name' => 'Example Client',
     *         'domain' => 'client.com',
     *         'active' => true
     *     ]
     * ]
     */
    public function __construct(array $clientStore = []) {
        $this->clientStore = $clientStore;
    }

    /**
     * {@inheritdoc}
     */
    public function getClient($id) {
        foreach($this->clientStore as $clientId => $client) {
            if((integer) $clientId === (integer) $id) {
                return new Client($clientId, $client['name'], $client['domain'], $client['secret'], isset($client['active'])? $client['active'] : true);
            }
        }
    }
}
