<?php

namespace Renegare\Soauth;

use Symfony\Component\Security\Core\User\User;

class AccessUserProvider implements AccessUserProviderInterface {

    protected $userStore;

    public function __construct(array $userStore = []) {
        $this->userStore = $userStore;
    }

    /**
     * {@inheritdoc}
     */
    public function getUsernameUser($usernameKey) {
        foreach($this->userStore as $username => $user) {
            if($username === $usernameKey) {
                return new User($username, $user['password'], isset($user['roles'])? $user['roles'] : [], isset($user['enabled'])? !!$user['enabled'] : []);
            }
        }
    }
}
