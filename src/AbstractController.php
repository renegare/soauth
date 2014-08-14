<?php

namespace Renegare\Soauth;

use Symfony\Component\Validator\Validation;
use Symfony\Component\Validator\Constraints\Collection;

use Psr\Log\LoggerInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerTrait;
use Psr\Log\LoggerAwareTrait;

abstract class AbstractController implements LoggerAwareInterface, LoggerInterface {
    use LoggerTrait, LoggerAwareTrait;

    /**
     * {@inheritdoc}
     */
    public function log($level, $message, array $context = array()) {
        if($this->logger) {
            $this->logger->log($level, $message, $context);
        }
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

            throw new BadRequestException('Invalid request data', $errors);
        }
    }
}
