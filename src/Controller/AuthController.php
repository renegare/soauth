<?php

namespace Renegare\Soauth\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\ParameterBag;

use Renegare\Soauth\Enum\ResponseType;
use Renegare\Soauth\RendererInterface;
use Renegare\Soauth\AccessProvider\AccessProviderInterface;
use Renegare\Soauth\Exception\SoauthException;
use Renegare\Soauth\AccessStorageHandler\AccessStorageHandlerInterface;

class AuthController extends AbstractController {

    protected $renderer;
    protected $accessProvider;
    protected $accessStore;
    protected $securityContext;

    /**
     * @param RendererInterface $renderer
     * @param AccessProviderInterface $accessProvider
     * @param StorageHandlerInterface $store
     */
    public function __construct(RendererInterface $renderer, AccessProviderInterface $accessProvider, AccessStorageHandlerInterface $store) {
        $this->renderer = $renderer;
        $this->accessProvider = $accessProvider;
        $this->accessStore = $store;
    }

    /**
     * verify authentication request and display entry point to authenticate
     * @param $request
     * @return string|Response
     */
    public function signinAction(Request $request) {
        $data = $request->query;
        $this->verifyData($data);

        $responseType = $data->get('response_type');
        if(!ResponseType::isSupported($responseType)) {
            throw new SoauthException(sprintf('response type \'%s\' not supported.', $responseType));
        }

        $response = new Response($this->renderer->renderSignInForm($data->all()));

        return $response;
    }

    /**
     * authenticate user
     * @param $request
     * @return string|Response
     */
    public function authenticateAction(Request $request) {
        $data = $request->request;
        $this->verifyData($data);

        $client = $data->get('client');
        $user = $this->getUser($data->get('username'));

        if(!$this->userProvider->isValid($user, $data->get('password'))) {
            $data->set('error', 'Bad username and password combination');
            $response = new Response($this->renderer->renderSignInForm($data->all()), Response::HTTP_BAD_REQUEST);
        } else {
            $access = $this->accessProvider->generateAuthorizationCodeAccess($user, $client);
            $this->accessStore->save($access);
            $response = new RedirectResponse($data->get('redirect_uri') . '?code=' . $access->getAuthCode());
        }

        return $response;
    }

    protected function verifyData(ParameterBag $data) {
        $client = $this->getClient($data->get('client_id'));
        if(!$client->isActive() || !$client->isValidRedirectUri($data->get('redirect_uri'))) {
            throw new SoauthException(sprintf('Invalid client request. Client id %s', $client_id));
        }
        $data->set('client', $client);
    }
}
