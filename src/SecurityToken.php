<?php

namespace Renegare\Soauth;

use Renegare\Soauth\Access\Access;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class SecurityToken extends AbstractToken {

    protected $access;

    /**
     * @param Access $access
     */
    public function __construct(Access $access) {
        parent::__construct([]);
        $this->access = $access;
    }

    /**
     * {@inheritdoc}
     * @return Access
     */
    public function getCredentials() {
        return $this->access;
    }
}
