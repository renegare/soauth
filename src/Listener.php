<?php

namespace Renegare\Soauth;

use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\HttpFoundation\Request;

class Listener extends AbstractLogger {

    /** @var SecurityContextInterface */
    protected $securityContext;
    /** @var strings */
    protected $firewallName;
    /** @var AccessProviderInterface */
    protected $accessProvider;

    public function __construct($firewallName, SecurityContextInterface $securityContext, AccessProviderInterface $accessProvider) {
        $this->firewallName = $firewallName;
        $this->securityContext = $securityContext;
        $this->accessProvider = $accessProvider;
    }

    /**
     * {@inheritdoc}
     * @param $event GetResponseEvent
     */
    public function handle(GetResponseEvent $event) {
        $request = $event->getRequest();

        try {
            $token = $this->getAccessToken($request);
            $this->info('User appears to be logged in already. #Noop', ['token' => $token->getAttributes()]);
            $this->securityContext->setToken($token);
        } catch (BadRequestException $e) {
            $this->error('Soauth Listener ' . $e->getMessage(), ['exception' => $e]);
            $response = new Response(json_encode($e->getMessage()), $e->getCode());
            $event->setResponse($response);
        }
    }

    public function getAccessToken(Request $request) {
        if(!$request->headers->has('X-ACCESS-CODE')) {
            $exception = new BadRequestException($request, 'Access code header not present in request', Response::HTTP_UNAUTHORIZED);
            throw $exception;
        }

        try {
            $accessCode = $request->headers->get('X-ACCESS-CODE');
            return $this->accessProvider->getAccessToken($accessCode);
        } catch (SoauthException $e) {
            $exception = new BadRequestException($request, 'No valid access code found', Response::HTTP_UNAUTHORIZED, $e);
            throw $exception;
        }
    }
}
