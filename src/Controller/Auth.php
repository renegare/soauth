<?php

namespace Renegare\Soauth\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\JsonResponse;

use Symfony\Component\Validator\Constraints\Regex;
use Symfony\Component\Validator\Constraints\Url;
use Symfony\Component\Validator\Constraints\NotBlank;

use Renegare\Soauth\RendererInterface;
use Renegare\Soauth\AccessProviderInterface;
use Renegare\Soauth\ClientProviderInterface;
use Renegare\Soauth\BadDataException;
use Renegare\Soauth\AbstractController;
use Renegare\Soauth\SoauthException;
use Renegare\Soauth\AccessStorageHandler\AccessStorageHandlerInterface;

class Auth extends AbstractController {

    const GT_AUTHORIZATION_CODE = 'authorization_code';
    const GT_CLIENT_CREDENTIALS = 'client_credentials';

    protected $renderer;
    protected $accessProvider;
    protected $clientProvider;
    protected $credentialStore;

    /**
     * @param RendererInterface $renderer
     * @param AccessProviderInterface $accessProvider
     * @param ClientProviderInterface $clientProvider
     * @param StorageHandlerInterface $store
     */
    public function __construct(RendererInterface $renderer, AccessProviderInterface $accessProvider, ClientProviderInterface $clientProvider, AccessStorageHandlerInterface $store) {
        $this->renderer = $renderer;
        $this->accessProvider = $accessProvider;
        $this->clientProvider = $clientProvider;
        $this->credentialStore = $store;
    }

    /**
     * verify authentication request and display entry point to authenticate
     * @param $request
     * @return string|Response
     */
    public function signinAction(Request $request) {
        try {
            $data = $this->getAuthClientIdentifiers($request);

            // exports $client_id, $redirect_uri
            extract($data);

            if(!(($client = $this->clientProvider->getClient($client_id)) && $this->clientProvider->isValid($client, $redirect_uri))) {
                throw new SoauthException(sprintf('No client found with id %s', $client_id));
            }

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

        $this->debug('< Response', ['status_code' => $response->getStatusCode()]);
        return $response;
    }

    /**
     * authenticate user
     * @param $request
     * @return string|Response
     */
    public function authenticateAction(Request $request) {
        $grantType = $request->request->get('grant_type', 'authorization_code');

        switch($grantType) {
            case self::GT_CLIENT_CREDENTIALS:
                $response = $this->grantClientCredentials($request);
                break;
            case self::GT_AUTHORIZATION_CODE:
                $response = $this->grantAuthorizationCode($request);
                break;
            default:
                $response = $this->getBadRequestResponse('Invalid Grant Type Request');
                break;
        }

        return $response;
    }

    protected function grantClientCredentials(Request $request) {
        $requestData = $request->request;
        $clientId = $requestData->get('client_id', null);
        $clientSecret = $requestData->get('client_secret', null);

        if(!($client = $this->clientProvider->getClient($clientId))) {
            throw new SoauthException(sprintf('No client found with id %s', $client_id));
        }

        if(!($client->getSecret() === $clientSecret && $client->isActive())) {
            throw new SoauthException(sprintf('No client found with id %s', $client_id));
        }

        $credentials = $this->accessProvider->generateClientCredentialsAccess($client);
        $this->credentialStore->save($credentials);

        return new JsonResponse($credentials->toArray());
    }

    protected function grantAuthorizationCode(Request $request) {
        $data = $request->request->all();
        try {
            $data = $this->getAuthCredentials($request);
            $this->debug('> Authenticate request', ['method' => $request->getMethod(), 'query' => $data]);
            // exports $client_id, $redirect_uri, $username and $password
            extract($data);

            $accessCredentials = $this->accessProvider->generate($request, $client_id, $redirect_uri, $username, $password);
            $response = new RedirectResponse($redirect_uri . '?code=' . $accessCredentials->getAuthCode());
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
