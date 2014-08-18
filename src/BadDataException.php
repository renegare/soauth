<?php

namespace Renegare\Soauth;

class BadDataException extends SoauthException {

    protected $errors;

    /**
     * @param array $errors
     * @param string $message
     * @param integer $code
     * @param Exception $previous
     */
    public function __construct (array $errors, $message = '', $code = 0, \Exception $previous = NULL) {
        $this->errors = $errors;
        parent::__construct($message, $code, $previous);
    }

    /**
     * @return array
     */
    public function getErrors() {
        return $this->errors;
    }
}
