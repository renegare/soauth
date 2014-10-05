<?php

namespace Renegare\Soauth;

use Renegare\Soauth\Access\Access;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class SecurityToken extends AbstractToken {

    protected $access;

    /**
     * @param Access $access
     */
    public function __construct(Access $access, array $roles = []) {
        parent::__construct($roles);
        $this->access = $access;
    }

    /**
     * @return Access
     */
    public function getAccess() {
        return $this->access;
    }

    /**
     * {@inheritdoc}
     * @return Access
     */
    public function getCredentials() {
        return $this->getAccess();
    }
}
