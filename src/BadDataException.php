<?php

namespace Renegare\Soauth;

use Symfony\Component\HttpFoundation\Request;

class BadDataException extends \RuntimeException {

    protected $errors;

    public function __construct (array $errors, $message = '', $code = 0, \Exception $previous = NULL) {
        $this->errors = $errors;
        parent::__construct($message, $code, $previous);
    }

    public function getErrors() {
        return $this->errors;
    }
}
