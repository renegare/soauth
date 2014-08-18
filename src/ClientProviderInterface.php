<?php

namespace Renegare\Soauth;

interface ClientProviderInterface {
    /**
     * find client given an id
     * @param string|integer $id - unique client identifier
     * @return ClientInterface|string|null
     */
    public function getClient($id);

    /**
     * validate client
     * @param ClientInterface $client
     * @param string $redirectUri - requested callback url
     * @return boolean
     */
    public function isValid(ClientInterface $client, $redirectUri);
}
