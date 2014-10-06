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
    public function signinAction(Request $request) {
        try {
            $responseType = $request->query->get('response_type');

            if(!ResponseType::isSupported($responseType)) {
                throw new SoauthException(sprintf('response type \'%s\' not supported.', $responseType));
            }

            $data = $this->getAuthClientIdentifiers($request);

            // exports $client_id, $redirect_uri
            extract($data);

            if(!(($client = $this->clientProvider->getClient($client_id)) && $this->clientProvider->isValid($client, $redirect_uri))) {
                throw new SoauthException(sprintf('No client found with id %s', $client_id));
            }

            $data['response_type'] = $responseType;
            $data['client'] = $client;

            $this->debug('> Sign in request', ['method' => $request->getMethod(), 'query' => $data]);
            $response = new Response($this->renderer->renderSignInForm($data));
        } catch (BadDataException $e) {
            $this->error('Bad Data Exception: ' . $e->getMessage(), ['errors' => $e->getErrors(), 'exception' => $e]);
            $response = $this->getBadRequestResponse();
        } catch (SoauthException $e) {
            $this->error('Soauth Exception: ' . $e->getMessage(), ['exception' => $e]);
            $response = $this->getBadRequestResponse();
        }

        return $response;
    }

    /**
     * authenticate user
     * @param $request
     * @return string|Response
     */
    public function authenticateAction(Request $request) {
        $data = $request->request->all();
        try {
            $data = $this->getAuthCredentials($request);
            $this->debug('> Authenticate request', ['method' => $request->getMethod(), 'query' => $data]);
            // exports $client_id, $redirect_uri, $username and $password
            extract($data);

            $client = $this->getClient($client_id);
            $user = $this->getUser($username);

            $access = $this->accessProvider->generateAuthorizationCodeAccess($user, $client);
            $this->credentialStore->save($access);
            $response = new RedirectResponse($redirect_uri . '?code=' . $access->getAuthCode());
        }catch (BadDataException $e) {
            $data['errors'] = $e->getErrors();
            $this->error('Bad Data Exception: ' . $e->getMessage(), ['errors' => $data['errors'], 'exception' => $e]);
            $response = $this->getBadFormRequestResponse($data);
        } catch (SoauthException $e) {
            $this->error('Soauth Exception: ' . $e->getMessage(), ['exception' => $e]);
            $response = $this->getBadFormRequestResponse($data);
        }

        $this->debug('< Response', ['status_code' => $response->getStatusCode(), 'target' => $response instanceOf RedirectResponse ? $response->getTargetUrl() : null]);
        return $response;
    }

    protected function getBadRequestResponse($content = 'Error') {
        return new Response($content, Response::HTTP_BAD_REQUEST);
    }

    protected function getBadFormRequestResponse($data = []) {
        $content = $this->renderer->renderSignInForm($data);
        return $this->getBadRequestResponse($content);
    }

    protected function getAuthClientIdentifiers(Request $request) {
        $constraints = [
                'client_id' => [new NotBlank, new Regex(['pattern' => '/^\d+$/'])],
                'redirect_uri' => [new NotBlank, new Url]
            ];

        $data = [
            'client_id' => $request->query->get('client_id'),
            'redirect_uri' => $request->query->get('redirect_uri')
        ];

        $this->validate($constraints, $data);

        return $data;
    }

    protected function getAuthCredentials(Request $request) {
        $constraints = [
            'client_id' => [new NotBlank, new Regex(['pattern' => '/^\d+$/'])],
            'redirect_uri' => [new NotBlank, new Url],
            'username' => [new NotBlank],
            'password' => [new NotBlank]
        ];

        $data = [
            'client_id' => $request->request->get('client_id'),
            'redirect_uri' => $request->request->get('redirect_uri'),
            'username' => $request->request->get('username'),
            'password' => $request->request->get('password')
        ];

        $this->validate($constraints, $data);

        return $data;
    }
}
