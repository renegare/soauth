<?php

namespace Renegare\Soauth;

use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder;

class AccessUserProvider implements AccessUserProviderInterface {

    protected $userStore;
    protected $digester;

    public function __construct(array $userStore = []) {
        $this->userStore = $userStore;
        $this->digester = new MessageDigestPasswordEncoder();
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

    public function isValid(UserInterface $user, $password = '') {
        return $user->getPassword() === $this->encodePassword($password);
    }

    public function encodePassword($password) {
        return $this->digester->encodePassword($password, '');
    }
}
