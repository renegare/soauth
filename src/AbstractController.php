<?php

namespace Renegare\Soauth;

use Symfony\Component\Validator\Validation;
use Symfony\Component\Validator\Constraints\Collection;

abstract class AbstractController implements LoggerInterface {
    use LoggerTrait;

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
}
