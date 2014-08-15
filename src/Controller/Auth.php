<?php

namespace Renegare\Soauth\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;

use Symfony\Component\Validator\Constraints\Regex;
use Symfony\Component\Validator\Constraints\Url;
use Symfony\Component\Validator\Constraints\NotBlank;

use Renegare\Soauth\RendererInterface;
use Renegare\Soauth\AccessProviderInterface;
use Renegare\Soauth\BadDataException;
use Renegare\Soauth\AbstractController;
use Renegare\Soauth\SoauthException;

class Auth extends AbstractController {

    /** @var RendererInterface */
    protected $renderer;
    /** @var AccessProviderInterface */
    protected $accessProvider;

    public function setRenderer(RendererInterface $renderer) {
        $this->renderer = $renderer;
    }

    public function setAccessProvider(AccessProviderInterface $accessProvider) {
        $this->accessProvider = $accessProvider;
    }

    public function signinAction(Request $request) {
        try {
            $data = $this->getAuthClientIdentifiers($request);
            $this->info('> Sign in request', ['method' => $request->getMethod(), 'query' => $data]);
            $response = new Response($this->renderer->renderSignInForm($data));
        } catch (BadDataException $e) {
            $this->error('Bad Data Exception: ' . $e->getMessage(), ['errors' => $e->getErrors(), 'exception' => $e]);
            $response = $this->getBadRequestResponse();
        } catch (SoauthException $e) {
            $this->error('Soauth Exception: ' . $e->getMessage(), ['exception' => $e]);
            $response = $this->getBadRequestResponse();
        }

        $this->info('< Response', ['status_code' => $response->getStatusCode()]);
        return $response;
    }

    public function authenticateAction(Request $request) {
        $data = $request->request->all();
        try {
            $data = $this->getAuthCredentials($request);
            $this->info('> Authenticate request', ['method' => $request->getMethod(), 'query' => $data]);
            // exports $client_id, $redirect_uri, $username and $password
            extract($data);

            $accessCredentials = $this->accessProvider->generate($client_id, $redirect_uri, $username, $password, $request);
            $response = new RedirectResponse($redirect_uri . '?code=' . $accessCredentials->getAuthCode());
        }catch (BadDataException $e) {
            $data['errors'] = $e->getErrors();
            $this->error('Bad Data Exception: ' . $e->getMessage(), ['errors' => $data['errors'], 'exception' => $e]);
            $response = $this->getBadFormRequestResponse($data);
        } catch (SoauthException $e) {
            $this->error('Soauth Exception: ' . $e->getMessage(), ['exception' => $e]);
            $response = $this->getBadFormRequestResponse($data);
        }

        $this->info('< Response', ['status_code' => $response->getStatusCode(), 'target' => $response instanceOf RedirectResponse ? $response->getTargetUrl() : null]);
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
