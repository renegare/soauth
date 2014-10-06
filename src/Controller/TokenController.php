<?php

namespace Renegare\Soauth\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\JsonResponse;

use Renegare\Soauth\GrantType;
use Renegare\Soauth\AccessProviderInterface;
use Renegare\Soauth\AccessStorageHandler\AccessStorageHandlerInterface;
use Renegare\Soauth\SoauthException;
use Renegare\Soauth\Access\AuthorizationCodeAccess;
use Renegare\Soauth\AuthorizationProvider\AuthorizationProviderInterface;

class TokenController extends AbstractController {

    protected $accessProvider;
    protected $accessStore;
    protected $authProvider;

    /**
     * @param AccessProviderInterface $accessProvider
     * @param StorageHandlerInterface $store
     */
    public function __construct(AccessProviderInterface $accessProvider, AccessStorageHandlerInterface $accessStore, AuthorizationProviderInterface $authProvider) {
        $this->accessProvider = $accessProvider;
        $this->accessStore = $accessStore;
        $this->authProvider = $authProvider;
    }

    public function grantAction(Request $request) {
        $grantType = $request->request->get('grant_type');

        if(!GrantType::isSupported($grantType)) {
            throw new SoauthException(sprintf('grant type \'%s\' not supported.', $grantType));
        }

        switch($grantType) {
            case GrantType::CLIENT_CREDENTIALS:
                $response = $this->grantClientCredentials($request);
                break;
            case GrantType::AUTHORIZATION_CODE:
                $response = $this->grantAuthorizationCode($request);
                break;
            case GrantType::REFRESH_TOKEN:
                $response = $this->grantRefreshToken($request);
                break;
        }

        return $response;
    }

    protected function grantAuthorizationCode(Request $request) {
        $data = $request->request;
        $authCode = $data->get('code');
        $clientId = $data->get('client_id');
        $clientSecret = $data->get('client_secret');
        $client = $this->getClient($clientId);
        $access = $this->accessStore->getAuthorizationCodeAccess($authCode);

        if(!$client || $clientSecret !== $client->getSecret() || $access->getClientId() !== $client->getId()) {
            throw new SoauthException('Invalid client trying to request an auth_code exchange, client id: ' . $access->getClientId());
        }

        $response = new JsonResponse([
            'access_token' => $access->getAccessToken(),
            'refresh_token' => $access->getRefreshToken(),
            'expires_in' => $access->getExpiresIn()
        ]);

        return $response;
    }

    protected function grantRefreshToken(Request $request) {
        $data = $request->request;
        $refreshToken = $data->get('refresh_token');
        $clientId = $data->get('client_id');
        $clientSecret = $data->get('client_secret');

        if(!($client = $this->getClient($clientId)) || $client->getSecret() !== $clientSecret) {
            throw new SoauthException(sprintf('No client found with id %s', $clientId));
        }

        $accessToken = $this->authProvider->getAuth($request);
        $currentAccess = $this->accessStore->getAccess($accessToken);

        if($currentAccess->getRefreshToken() !== $refreshToken) {
            throw new SoauthException('refresh token does not match authorized request');
        }

        $user = null;
        if($currentAccess instanceOf AuthorizationCodeAccess) {
            $user = $this->getUser($currentAccess->getUsername());
        }

        $refreshedAccess = $this->accessProvider->refreshAccess($currentAccess, $client, $user);
        $this->accessStore->save($refreshedAccess);
        $this->accessStore->invalidate($currentAccess);

        $response = new JsonResponse([
            'access_token' => $refreshedAccess->getAccessToken(),
            'refresh_token' => $refreshedAccess->getRefreshToken(),
            'expires_in' => $refreshedAccess->getExpiresIn()
        ]);

        $this->debug('< Response', ['status_code' => $response->getStatusCode()]);

        return $response;
    }

    protected function grantClientCredentials(Request $request) {
        $data = $request->request;
        $clientId = $data->get('client_id');
        $clientSecret = $data->get('client_secret');

        if(!($client = $this->clientProvider->getClient($clientId))) {
            throw new SoauthException(sprintf('No client found with id %s', $clientId));
        }

        if(!($client->getSecret() === $clientSecret && $client->isActive())) {
            throw new SoauthException(sprintf('No client found with id %s', $clientId));
        }

        $access = $this->accessProvider->generateClientCredentialsAccess($client);
        $this->accessStore->save($access);

        return new JsonResponse([
            'access_token' => $access->getAccessToken(),
            'refresh_token' => $access->getRefreshToken(),
            'expires_in' => $access->getExpiresIn()
        ]);
    }
}
