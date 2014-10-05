<?php

namespace Renegare\Soauth\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

use Symfony\Component\Validator\Constraints\NotBlank;

use Renegare\Soauth\AccessProviderInterface;
use Renegare\Soauth\ClientProviderInterface;
use Renegare\Soauth\UserProviderInterface;
use Renegare\Soauth\AbstractController;
use Renegare\Soauth\BadDataException;
use Renegare\Soauth\SoauthException;
use Renegare\Soauth\AccessStorageHandler\AccessStorageHandlerInterface;

/**
 * @todo: this controller needs to expect+verify a client secret ... else anyone can gain
 * an access token with a valid a auth or refresh code!!
 */
class Access extends AbstractController {

    const RT_CODE = 'code';
    const GT_AUTHORIZATION_CODE = 'authorization_code';

    /** @var AccessProviderInterface */
    protected $accessProvider;
    protected $clientProvider;
    protected $userProvider;
    protected $accessStore;

    public function __construct(AccessProviderInterface $accessProvider, ClientProviderInterface $clientProvider, UserProviderInterface $userProvider, AccessStorageHandlerInterface $accessStore) {
        $this->accessProvider = $accessProvider;
        $this->clientProvider = $clientProvider;
        $this->userProvider = $userProvider;
        $this->accessStore = $accessStore;
    }

    /**
     * exchange auth for an access code
     * @param $request
     * @return string|Response
     */
    public function exchangeAction(Request $request) {
        try {
            $grantType = $request->request->get('grant_type');

            if($grantType !== self::GT_AUTHORIZATION_CODE) {
                throw new SoauthException(sprintf('grant type \'%s\' not supported.', $grantType));
            }

            $authCode = $request->request->get('code');
            $clientId = $request->request->get('client_id');
            $clientSecret = $request->request->get('client_secret');

            $access = $this->accessStore->getAuthorizationCodeAccess($authCode);
            $client = $this->getClient($access->getClientId());

            if(!$client || $clientSecret !== $client->getSecret()) {
                throw new SoauthException('Invalid client trying to request an auth_code exchange, client id: ' . $access->getClientId());
            }

            $this->debug('> Exchange request', ['method' => $request->getMethod(), 'auth_code' => $authCode]);

            $response = new JsonResponse([
                'access_token' => $access->getAccessToken(),
                'refresh_token' => $access->getRefreshToken(),
                'expires_in' => $access->getExpiresIn()
            ]);
        } catch (SoauthException $e) {
            $data = [];

            if($e instanceof BadDataException) {
                $data['errors'] = $e->getErrors();
            }

            $response = new JsonResponse($data, Response::HTTP_BAD_REQUEST);
        }

        $this->debug('< Response', ['status_code' => $response->getStatusCode()]);

        return $response;
    }

    /**
     * refresh a given access credentials
     * @param $request
     * @return string|Response
     */
    public function refreshAction(Request $request) {
        try {
            $refreshCode = $this->getRefreshCode($request);

            $clientSecret = $this->getClientSecret($request);
            $credentials = $this->accessProvider->refresh($request, $refreshCode, $clientSecret);

            $response = new JsonResponse([
                'access_code' => $credentials->getAccessCode(),
                'refresh_code' => $credentials->getRefreshCode(),
                'lifetime' => $credentials->getLifetime()
            ]);
        } catch (SoauthException $e) {
            $data = [];

            if($e instanceof BadDataException) {
                $data['errors'] = $e->getErrors();
            }

            $response = new JsonResponse($data, Response::HTTP_BAD_REQUEST);
        }

        $this->debug('< Response', ['status_code' => $response->getStatusCode()]);

        return $response;
    }

    protected function getAuthCode(Request $request) {
        $constraints = ['code' => [new NotBlank]];

        $data = @json_decode($request->getContent(), true);

        $this->validate($constraints, $data? $data : []);

        return $data['code'];
    }

    protected function getRefreshCode(Request $request) {
        $constraints = ['refresh_code' => [new NotBlank]];

        $data = ['refresh_code' => $request->request->get('refresh_code')];

        $this->validate($constraints, $data);

        return $data['refresh_code'];
    }

    protected function getClientSecret(Request $request) {
        return $request->headers->get('X-CLIENT-SECRET', '');
    }

    protected function getUser($username) {
        if(!($user = $this->userProvider->getUser($username))) {
            throw new SoauthException(sprintf('No user found with username %s', $username));
        }
        return $user;
    }

    protected function getClient($clientId) {
        if(!($client = $this->clientProvider->getClient($clientId))) {
            throw new SoauthException(sprintf('No client found with id %s', $clientId));
        }
        return $client;
    }
}
