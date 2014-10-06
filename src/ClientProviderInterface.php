<?php

namespace Renegare\Soauth;

interface ClientProviderInterface {
    /**
     * find client given an id
     * @param string|integer $id - unique client identifier
     * @return ClientInterface|string|null
     */
    public function getClient($id);
}
