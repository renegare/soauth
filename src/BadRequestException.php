<?php

namespace Renegare\Soauth;

class BadRequestException extends \RuntimeException {

    protected $errors;

    public function __construct ($message = '', array $errors = [], $code = 0, \Exception $previous = NULL) {
        $this->errors = $errors;
        parent::__construct($message, $code, $previous);
    }

    public function getErrors() {
        return $this->errors;
    }
}
