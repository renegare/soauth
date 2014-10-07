<?php

namespace Renegare\Soauth\AccessProvider;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserInterface;

use Renegare\Soauth\Access\ClientCredentialsAccess;
use Renegare\Soauth\Access\AuthorizationCodeAccess;
use Renegare\Soauth\Access\Access;
use Renegare\Soauth\Client\ClientInterface;

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
     * @return Access
     */
    public function refreshAccess(Access $access, ClientInterface $client, UserInterface $user = null);
}
