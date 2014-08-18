<?php

namespace Renegare\Soauth;

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
     */
    public function __construct($id, $name, $domain, $secret, $active = true) {
        $this->id = $id;
        $this->name = $name;
        $this->domain = $domain;
        $this->secret = $secret;
        $this->active = $active;
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

}
