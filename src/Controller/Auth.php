<?php

namespace Renegare\Soauth\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;

use Symfony\Component\Validator\Validation;
use Symfony\Component\Validator\Constraints\Collection;
use Symfony\Component\Validator\Constraints\Regex;
use Symfony\Component\Validator\Constraints\Url;
use Symfony\Component\Validator\Constraints\NotBlank;

use Renegare\Soauth\RendererInterface;
use Renegare\Soauth\ClientProviderInterface;
use Renegare\Soauth\UserProviderInterface;
use Renegare\Soauth\AccessProviderInterface;
use Renegare\Soauth\BadRequestException;
use Renegare\Soauth\AbstractController;

class Auth extends AbstractController {

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
        try {
            $data = $this->getAuthClientIdentifiers($request);
            $response = $this->renderer->renderSignInForm($data);
        } catch (BadRequestException $e) {
            $response = new Response('Error', Response::HTTP_BAD_REQUEST);
        }

        return $response;
    }

    public function authenticateAction(Request $request) {
        try {
            $data = $this->getAuthCredentials($request);

            // exports $client_id, $redirect_uri, $username and $password
            extract($data);

            $client = $this->clientProvider->load($client_id);
            $user = $this->userProvider->loadByUsername($username);

            if($user->isValidPassword($password)) {
                $accessCredentials = $this->accessProvider->generateAccessCredentials($client, $user, $request->getClientIp());
                $response = new RedirectResponse($redirect_uri . '?code=' . $accessCredentials->getAuthCode());
            }
        } catch (\Exception $e) {
            $data = $request->request->all();
            if($e instanceof BadRequestException) {
                $data['errors'] = $e->getErrors();
            }

            $content = $this->renderer->renderSignInForm($data);
            $response = new Response($content, Response::HTTP_BAD_REQUEST);
        }

        return $response;
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

    protected function validate(array $constraints, array $data) {

        $validator = Validation::createValidatorBuilder()
            ->setApiVersion(Validation::API_VERSION_2_4)
            ->getValidator();

        $violations = $validator->validateValue($data, new Collection([
            'fields' => $constraints,
            'allowExtraFields' => false,
            'allowMissingFields' => false
        ]));

        if(count($violations)) {
            $errors = [];
            foreach($violations as $violation) {
                $path = preg_replace('/[\[\]]/', '', $violation->getPropertyPath());
                $errors[$path] = $violation->getMessage();
            }

            throw new BadRequestException('Invalid authentication request', $errors);
        }
    }
}
