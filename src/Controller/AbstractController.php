<?php

namespace Renegare\Soauth\Controller;

use Symfony\Component\Validator\Validation;
use Symfony\Component\Validator\Constraints\Collection;
use Renegare\Soauth\BadDataException;
use Renegare\Soauth\LoggerInterface;
use Renegare\Soauth\LoggerTrait;
use Renegare\Soauth\ClientProviderInterface;
use Renegare\Soauth\UserProviderInterface;

abstract class AbstractController implements LoggerInterface {
    use LoggerTrait;

    protected $userProvider;
    protected $clientProvider;

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

            throw new BadDataException($errors, 'Invalid request data');
        }
    }

    public function setUserProvider(UserProviderInterface $provider) {
        $this->userProvider = $provider;
    }

    public function setClientProvider(ClientProviderInterface $provider) {
        $this->clientProvider = $provider;
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
