<?php

namespace Renegare\Soauth;

interface ClientProviderInterface {

    /**
     * load a client using the client id
     * @param $id integer
     * @return ClientInterface
     */
    public function load($id);
}
