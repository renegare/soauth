<?php

namespace Renegare\Soauth;

use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder;

class UserProvider implements UserProviderInterface {

    protected $userStore;
    protected $digester;

    public function __construct(array $userStore = []) {
        $this->userStore = $userStore;
        $this->digester = new MessageDigestPasswordEncoder();
    }

    /**
     * {@inheritdoc}
     */
    public function getUser($usernameKey) {
        foreach($this->userStore as $username => $user) {
            if($username === $usernameKey) {
                return new User($username, $user['password'], isset($user['roles'])? $user['roles'] : [], isset($user['enabled'])? !!$user['enabled'] : []);
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(UserInterface $user, $password = '') {
        return $user->getPassword() === $this->encodePassword($password);
    }

    /**
     * encode password according to the what is expected
     * @param string $password
     * @param string $salt
     * @return string
     */
    public function encodePassword($password, $salt='') {
        return $this->digester->encodePassword($password, $salt);
    }
}
