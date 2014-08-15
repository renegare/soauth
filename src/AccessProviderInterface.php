<?php

namespace Renegare\Soauth;

use Symfony\Component\HttpFoundation\Request;

interface AccessProviderInterface {

    /**
     * load a client using the client id
     * @param $client ClientInterface
     * @param $user UserInterface
     * @param $ip string
     * @return CredentialsInterface
     */
    public function generate($clientId, $redirecUri, $username, $password, Request $request);

    /**
     * get access credentials for the given auth code
     * @param $authCode string
     * @return CredentialsInterface
     */
    public function exchange($authCode);

    /**
     * get security access token (that contains credentials) for the given access code
     * @param $accessCode string
     * @return AccessToken
     */
    public function getAccessToken($accessCode);

    /**
     * generate a new set of credentials from the old one
     * @param $refreshCode string
     * @return CredentialsInterface
     */
    public function refresh($refreshCode);
}
