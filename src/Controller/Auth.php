<?php

namespace Renegare\Soauth\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;

use Renegare\Soauth\RendererInterface;
use Renegare\Soauth\ClientProviderInterface;
use Renegare\Soauth\UserProviderInterface;
use Renegare\Soauth\AccessProviderInterface;

class Auth {

    /** @var RendererInterface */
    protected $renderer;
    /** @var ClientProviderInterface */
    protected $clientProvider;
    /** @var UserProviderInterface */
    protected $userProvider;
    /** @var AccessProviderInterface */
    protected $accessProvider;

    public function setRenderer(RendererInterface $renderer) {
        $this->renderer = $renderer;
    }

    public function setUserProvider(UserProviderInterface $userProvider) {
        $this->userProvider = $userProvider;
    }

    public function setClientProvider(ClientProviderInterface $clientProvider) {
        $this->clientProvider = $clientProvider;
    }

    public function setAccessProvider(AccessProviderInterface $accessProvider) {
        $this->accessProvider = $accessProvider;
    }

    public function signinAction(Request $request) {
        $data = $this->getAuthClientIdentifiers($request);
        return $this->renderer->renderSignInForm($data);
    }

    public function authenticateAction(Request $request) {
        $data = $this->getAuthCredentials($request);

        // exports $client_id, $redirect_uri, $username and $password
        extract($data);

        $client = $this->clientProvider->load($client_id);
        $user = $this->userProvider->loadByUsername($username);

        if($user->isValidPassword($password)) {
            $accessCredentials = $this->accessProvider->generateAccessCredentials($client, $user, $request->getClientIp());
            $response = new RedirectResponse($redirect_uri . '?code=' . $accessCredentials->getAuthCode());
        }

        return $response;
    }

    protected function getAuthClientIdentifiers(Request $request) {
        $clientId = $request->query->get('client_id');
        $redirectUri = $request->query->get('redirect_uri');

        return [
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri
        ];
    }

    protected function getAuthCredentials(Request $request) {
        $clientId = $request->request->get('client_id');
        $redirectUri = $request->request->get('redirect_uri');
        $username = $request->request->get('username');
        $password = $request->request->get('password');

        return [
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'username' => $username,
            'password' => $password
        ];
    }
}
