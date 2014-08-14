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

    /**
     * get access credentials for the given auth code
     * @param $authCode string
     * @return CredentialsInterface
     */
    public function getAccessCredentials($authCode);

    /**
     * generate a new set of credentials from the old one
     * @param $refreshCode string
     * @return CredentialsInterface
     */
    public function refresh($refreshCode);
}
