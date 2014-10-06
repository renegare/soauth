<?php

namespace Renegare\Soauth\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\JsonResponse;

use Symfony\Component\Security\Core\SecurityContextInterface;

use Symfony\Component\Validator\Constraints\Regex;
use Symfony\Component\Validator\Constraints\Url;
use Symfony\Component\Validator\Constraints\NotBlank;

use Renegare\Soauth\ResponseType;
use Renegare\Soauth\GrantType;
use Renegare\Soauth\RendererInterface;
use Renegare\Soauth\AccessProviderInterface;
use Renegare\Soauth\ClientProviderInterface;
use Renegare\Soauth\UserProviderInterface;
use Renegare\Soauth\BadDataException;
use Renegare\Soauth\SoauthException;
use Renegare\Soauth\AccessStorageHandler\AccessStorageHandlerInterface;
use Renegare\Soauth\Access\AuthorizationCodeAccess;

class AuthController extends AbstractController {

    protected $renderer;
    protected $accessProvider;
    protected $credentialStore;
    protected $securityContext;

    /**
     * @param RendererInterface $renderer
     * @param AccessProviderInterface $accessProvider
     * @param StorageHandlerInterface $store
     */
    public function __construct(RendererInterface $renderer, AccessProviderInterface $accessProvider, AccessStorageHandlerInterface $store) {
        $this->renderer = $renderer;
        $this->accessProvider = $accessProvider;
        $this->credentialStore = $store;
    }

    /**
     * verify authentication request and display entry point to authenticate
     * @param $request
     * @return string|Response
     */
    protected function verifyData($data) {
        $client = $this->getClient($data->get('client_id'));
        if(!$client->isActive() || !$client->isValidRedirectUri($data->get('redirect_uri'))) {
            throw new SoauthException(sprintf('Invalid client request. Client id %s', $client_id));
        }
        $data->set('client', $client);
    }

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
        //@todo validate password!?!

        $access = $this->accessProvider->generateAuthorizationCodeAccess($user, $client);
        $this->credentialStore->save($access);
        return new RedirectResponse($data->get('redirect_uri') . '?code=' . $access->getAuthCode());

    }
}
