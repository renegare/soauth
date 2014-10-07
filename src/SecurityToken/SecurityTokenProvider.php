<?php

namespace Renegare\Soauth\SecurityToken;

use Symfony\Component\HttpFoundation\Request;

use Renegare\Soauth\Exception\SoauthException;
use Renegare\Soauth\Access\AuthorizationCodeAccess;
use Renegare\Soauth\Access\ClientCredentialsAccess;
use Renegare\Soauth\ClientUserProviderTrait;
use Renegare\Soauth\AuthorizationProvider\AuthorizationProviderInterface;
use Renegare\Soauth\AccessStorageHandler\AccessStorageHandlerInterface;

class SecurityTokenProvider implements SecurityTokenProviderInterface {
    use ClientUserProviderTrait;

    protected $authProvider;
    protected $accessStorage;

    public function __construct(AuthorizationProviderInterface $authProvider, AccessStorageHandlerInterface $accessStorage) {
        $this->authProvider = $authProvider;
        $this->accessStorage = $accessStorage;
    }
    /**
     * {@inheritdoc}
     */
    public function getSecurityToken(Request $request) {
        $accessToken = $this->authProvider->getAuth($request);

        if(!($credentials = $this->accessStorage->getAccess($accessToken))) {
            throw new SoauthException(sprintf('No access found'));
        }

        if($credentials instanceOf AuthorizationCodeAccess) {
            $user = $this->getUser($credentials->getUsername());
        } else if($credentials instanceOf ClientCredentialsAccess) {
            $user = $this->getClient($credentials->getClientId());
        }

        $roles = $user->getRoles();

        $token = new SecurityToken($credentials, $roles);
        $token->setAuthenticated(true);
        $token->setUser($user);
        return $token;
    }
}
