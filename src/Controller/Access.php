<?php

namespace Renegare\Soauth\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

use Symfony\Component\Validator\Constraints\NotBlank;

use Renegare\Soauth\AccessProviderInterface;
use Renegare\Soauth\AbstractController;
use Renegare\Soauth\BadDataException;
use Renegare\Soauth\SoauthException;

class Access extends AbstractController {

    /** @var AccessProviderInterface */
    protected $accessProvider;

    public function setAccessProvider(AccessProviderInterface $accessProvider) {
        $this->accessProvider = $accessProvider;
    }

    public function exchangeAction(Request $request) {
        try {
            $authCode = $this->getAuthCode($request);

            $credentials = $this->accessProvider->exchange($authCode);

            $response = new JsonResponse([
                'access_code' => $credentials->getAccessCode(),
                'refresh_code' => $credentials->getRefreshCode(),
                'expires' => $credentials->getExpires()
            ]);
        } catch (SoauthException $e) {
            $data = [];

            if($e instanceof BadDataException) {
                $data['errors'] = $e->getErrors();
            }

            $response = new JsonResponse($data, Response::HTTP_BAD_REQUEST);
        }

        return $response;
    }

    public function refreshAction(Request $request) {
        try {
            $refreshCode = $this->getRefreshCode($request);

            $credentials = $this->accessProvider->refresh($refreshCode);

            $response = new JsonResponse([
                'access_code' => $credentials->getAccessCode(),
                'refresh_code' => $credentials->getRefreshCode(),
                'expires' => $credentials->getExpires()
            ]);
        } catch (SoauthException $e) {
            $data = [];

            if($e instanceof BadDataException) {
                $data['errors'] = $e->getErrors();
            }

            $response = new JsonResponse($data, Response::HTTP_BAD_REQUEST);
        }

        return $response;
    }

    protected function getAuthCode(Request $request) {
        $constraints = ['code' => [new NotBlank]];

        $data = ['code' => $request->request->get('code')];

        $this->validate($constraints, $data);

        return $data['code'];
    }

    protected function getRefreshCode(Request $request) {
        $constraints = ['refresh_code' => [new NotBlank]];

        $data = ['refresh_code' => $request->request->get('refresh_code')];

        $this->validate($constraints, $data);

        return $data['refresh_code'];
    }
}
