<?php

namespace Renegare\Soauth;

use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\SecurityContextInterface;

use Renegare\Soauth\Log\LoggerInterface;
use Renegare\Soauth\Log\LoggerTrait;
use Renegare\Soauth\Exception\SoauthException;
use Renegare\Soauth\SecurityToken\SecurityTokenProviderInterface;

class Listener implements ListenerInterface, LoggerInterface {
    use LoggerTrait;

    protected $securityContext;
    protected $firewallName;
    protected $authProvider;

    /**
     * @param string $firewallName
     * @param SecurityContextInterface $securityContext
     * @param SecurityTokenProviderInterface $tokenProvider
     */
    public function __construct($firewallName, SecurityContextInterface $securityContext, SecurityTokenProviderInterface $tokenProvider) {
        $this->firewallName = $firewallName;
        $this->securityContext = $securityContext;
        $this->tokenProvider = $tokenProvider;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(GetResponseEvent $event) {
        $request = $event->getRequest();

        $this->debug('> Security listener request', ['headers' => $request->headers->all()]);

        try {
            $token = $this->tokenProvider->getSecurityToken($request);
            $this->debug('User appears to be logged in already. #Noop', $token->getAccess()->toArray());
            $this->securityContext->setToken($token);
        } catch (SoauthException $e) {
            $this->error($e->getMessage(), ['exception' => $e]);
            $response = new JsonResponse('No valid authorization found', JsonResponse::HTTP_UNAUTHORIZED);
            $event->setResponse($response);
        }
    }
}
