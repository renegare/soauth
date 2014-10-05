<?php

namespace Renegare\Soauth;

use Symfony\Component\HttpFoundation\Request;
use Renegare\Soauth\Access\ClientCredentialsAccess;
use Renegare\Soauth\Access\AuthorizationCodeAccess;
use Renegare\Soauth\Access\Access;
use Symfony\Component\Security\Core\User\UserInterface;

interface AccessProviderInterface {
    /**
     * generate authorization code access
     * @param UserInterface $user
     * @param ClientInterface $client
     * @return AuthorizationCodeAccess
     */
    public function generateAuthorizationCodeAccess(UserInterface $user, ClientInterface $client);

    /**
     * generate client credentials access
     * @param ClientInterface $client
     * @return ClientCredentialsAccess
     */
    public function generateClientCredentialsAccess(ClientInterface $client);

    /**
     * generate a new set of credentials from the old one
     * @param Request $request
     * @param $refreshCode string
     * @return CredentialsInterface
     */
    public function refreshToken(Access $access);

    /**
     * get access credentials for the given auth code
     * @todo ... rethink this?!
     * @param string $authCode
     * @param string $clientSecret
     * @return CredentialsInterface
     */
    public function exchange($authCode, $clientSecret);
}
