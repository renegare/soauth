<?php

namespace Renegare\Soauth;

use Symfony\Component\HttpFoundation\Request;

interface AccessProviderInterface {

    /**
     * generate and store access credentials
     * @param Request $request
     * @param string $clientId
     * @param string $redirectUri
     * @param string $username
     * @param string $password [optional]
     * @return CredentialsInterface
     */
    public function generate(Request $request, $clientId, $redirecUri, $username, $password = '');

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
     * @param Request $request
     * @param $refreshCode string
     * @return CredentialsInterface
     */
    public function refresh(Request $request, $refreshCode);
}
