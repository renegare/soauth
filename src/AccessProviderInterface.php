<?php

namespace Renegare\Soauth;

interface AccessProviderInterface {

    /**
     * load a client using the client id
     * @param $client ClientInterface
     * @param $user UserInterface
     * @param $ip string
     * @return CredentialsInterface
     */
    public function generateAccessCredentials(ClientInterface $client, UserInterface $user, $ip='0.0.0.0');
}
