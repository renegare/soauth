<?php

namespace Renegare\Soauth;

use Symfony\Component\HttpFoundation\Request;

class BadRequestException extends SoauthException {

    protected $request;

    /**
     * @param array $errors
     * @param string $message
     * @param integer $code
     * @param Exception $previous
     */
    public function __construct (Request $request, $message = '', $code = 0, \Exception $previous = NULL) {
        $this->request = $request;
        parent::__construct($message, $code, $previous);
    }

    /**
     * @return Request
     */
    public function getRequest() {
        return $this->request;
    }
}
