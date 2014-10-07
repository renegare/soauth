<?php

namespace Renegare\Soauth\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;

use Renegare\Soauth\Enum\GrantType;
use Renegare\Soauth\AccessProvider\AccessProviderInterface;
use Renegare\Soauth\AccessStorageHandler\AccessStorageHandlerInterface;
use Renegare\Soauth\Exception\SoauthException;
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
        $client = $this->getValidClient($clientId, $clientSecret);

        $access = $this->accessStore->getAuthorizationCodeAccess($authCode);
        if(!$access || $access->getClientId() !== $client->getId()) {
            throw new SoauthException('Invalid authorization code');
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
        $client = $this->getValidClient($clientId, $clientSecret);

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
        $client = $this->getValidClient($clientId, $clientSecret);

        $access = $this->accessProvider->generateClientCredentialsAccess($client);
        $this->accessStore->save($access);

        return new JsonResponse([
            'access_token' => $access->getAccessToken(),
            'refresh_token' => $access->getRefreshToken(),
            'expires_in' => $access->getExpiresIn()
        ]);
    }
}
