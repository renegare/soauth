<?php

namespace Renegare\Soauth;

use Symfony\Component\HttpFoundation\Request;
use Renegare\Soauth\Access\ClientCredentialsAccess;
use Renegare\Soauth\Access\AuthorizationCodeAccess;

interface AccessProviderInterface {

    /**
     * get access credentials for the given auth code
     * @param string $authCode
     * @param string $clientSecret
     * @return CredentialsInterface
     */
    public function exchange($authCode, $clientSecret);

    /**
     * generate a new set of credentials from the old one
     * @param Request $request
     * @param $refreshCode string
     * @return CredentialsInterface
     */
    public function refresh(Request $request, $refreshCode);

    /**
     * generate and store access credentials
     * @todo needs to change!!!
     * @param Request $request
     * @param string $clientId
     * @param string $redirectUri
     * @param string $username
     * @param string $password [optional]
     * @return AuthorizationCodeAccess
     */
    public function generateAuthorizationCodeAccess(Request $request, $clientId, $redirecUri, $username, $password = '');

    /**
     * generate client access credentials
     * @param ClientInterface $client
     * @return ClientCredentialsAccess
     */
    public function generateClientCredentialsAccess(ClientInterface $client);
}
