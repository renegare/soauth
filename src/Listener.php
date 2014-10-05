<?php

namespace Renegare\Soauth;

use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\HttpFoundation\Request;

class Listener implements ListenerInterface, LoggerInterface {
    use LoggerTrait;

    protected $securityContext;
    protected $firewallName;
    protected $accessProvider;

    /**
     * @param string $firewallName
     * @param SecurityContextInterface $securityContext
     * @param SecurityAccessProviderInterface $accessProvider
     */
    public function __construct($firewallName, SecurityContextInterface $securityContext, SecurityAccessProviderInterface $accessProvider) {
        $this->firewallName = $firewallName;
        $this->securityContext = $securityContext;
        $this->accessProvider = $accessProvider;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(GetResponseEvent $event) {
        $request = $event->getRequest();

        $this->debug('> Security listener request', ['headers' => $request->headers->all()]);

        try {
            $token = $this->getAccessToken($request);
            $this->debug('User appears to be logged in already. #Noop', $token->getCredentials()->toArray());
            $this->securityContext->setToken($token);
        } catch (BadRequestException $e) {
            $this->error($e->getMessage(), ['exception' => $e]);
            $response = new JsonResponse($e->getMessage(), $e->getCode());
            $event->setResponse($response);
        }
    }

    protected function getAccessToken(Request $request) {
        if(!$request->headers->has('Authorization')) {
            $exception = new BadRequestException($request, 'Access code header not present in request', Response::HTTP_UNAUTHORIZED);
            throw $exception;
        }

        try {
            $accessToken = $this->parseAccessToken($request->headers->get('Authorization'));
            return $this->accessProvider->getSecurityToken($accessToken);
        } catch (SoauthException $e) {
            $this->error($e->getMessage(), ['exception' => $e]);
            $exception = new BadRequestException($request, 'No valid access code found', Response::HTTP_UNAUTHORIZED, $e);
            throw $exception;
        }
    }

    protected function parseAccessToken($authorization) {
        $authorization = explode(' ', $authorization);
        return trim($authorization[1]);
    }
}
