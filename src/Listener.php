<?php

namespace Renegare\Soauth;

use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\SecurityContextInterface;

use Renegare\Soauth\AuthorizationProvider\AuthorizationProviderInterface;
use Renegare\Soauth\AccessStorageHandler\AccessStorageHandlerInterface;
use Renegare\Soauth\Log\LoggerInterface;
use Renegare\Soauth\Log\LoggerTrait;
use Renegare\Soauth\Exception\SoauthException;

class Listener implements ListenerInterface, LoggerInterface {
    use LoggerTrait, ClientUserProviderTrait;

    protected $securityContext;
    protected $firewallName;
    protected $authProvider;

    /**
     * @param string $firewallName
     * @param SecurityContextInterface $securityContext
     * @param SecurityAccessProviderInterface $accessProvider
     */
    public function __construct($firewallName, SecurityContextInterface $securityContext, AuthorizationProviderInterface $authProvider, AccessStorageHandlerInterface $accessStorage) {
        $this->firewallName = $firewallName;
        $this->securityContext = $securityContext;
        $this->authProvider = $authProvider;
        $this->accessStorage = $accessStorage;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(GetResponseEvent $event) {
        $request = $event->getRequest();

        $this->debug('> Security listener request', ['headers' => $request->headers->all()]);

        try {
            $token = $this->getSecurityToken($request);
            $this->debug('User appears to be logged in already. #Noop', $token->getAccess()->toArray());
            $this->securityContext->setToken($token);
        } catch (SoauthException $e) {
            $this->error($e->getMessage(), ['exception' => $e]);
            $response = new JsonResponse('No valid authorization found', JsonResponse::HTTP_UNAUTHORIZED);
            $event->setResponse($response);
        }
    }

    /**
     * get security token
     * @param Request $request
     * @return SecurityToken
     */
    protected function getSecurityToken(Request $request) {
        $accessToken = $this->authProvider->getAuth($request);

        if(!($credentials = $this->accessStorage->getAccess($accessToken))) {
            throw new SoauthException(sprintf('No access found'));
        }

        if($credentials instanceOf Access\AuthorizationCodeAccess) {
            $user = $this->getUser($credentials->getUsername());
        } else if($credentials instanceOf Access\ClientCredentialsAccess) {
            $user = $this->getClient($credentials->getClientId());
        }

        // since client can have a specified role
        $roles = $user->getRoles();

        $token = new SecurityToken($credentials, $roles);
        $token->setAuthenticated(true);
        $token->setUser($user);
        return $token;
    }
}
