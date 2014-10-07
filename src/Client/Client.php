<?php

namespace Renegare\Soauth\Client;

class Client implements ClientInterface {
    protected $id;
    protected $name;
    protected $domain;
    protected $secret;
    protected $active;

    /**
     * @param string|integer $id
     * @param string $name
     * @param string $domain
     * @param string $secret
     * @param boolean $active
     * @param array $roles
     */
    public function __construct($id, $name, $domain, $secret, $active = true, array $roles = []) {
        $this->id = $id;
        $this->name = $name;
        $this->domain = $domain;
        $this->secret = $secret;
        $this->active = $active;
        $this->roles = $roles;
    }

    /**
     * {@inheritdoc}
     */
    public function getId() {
        return $this->id;
    }

    /**
     * {@inheritdoc}
     */
    public function getName() {
        return $this->name;
    }

    /**
     * {@inheritdoc}
     */
    public function isActive() {
        return !!$this->active;
    }

    /**
     * {@inheritdoc}
     */
    public function getDomain() {
        return $this->domain;
    }

    /**
     * {@inheritdoc}
     */
    public function getSecret() {
        return $this->secret;
    }

    /**
     * {@inheritdoc}
     */
    public function getRoles() {
        return $this->roles;
    }

    /**
     * {@inheritdoc}
     */
    public function getPassword() {
        return $this->getSecret();
    }

    /**
     * {@inheritdoc}
     */
    public function getSalt() {
        return null;
    }

     /**
      * {@inheritdoc}
      */
    public function getUsername() {
        return $this->id;
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials() {
        $this->secret = null;
    }

    /**
     * {@inheritdoc}
     */
    public function isValidRedirectUri($redirectUri) {
        $pattern = sprintf('/^https?:\\/\\/.*%s(?:\\/.*)?$/', preg_replace('/\./', '\\.', $this->getDomain()));
        return !!preg_match($pattern, $redirectUri);
    }
}
