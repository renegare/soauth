<?php

namespace Renegare\Soauth;

class Client implements ClientInterface {
    protected $id;
    protected $name;

    /**
     * @param string|integer $id
     * @param string $name
     */
    public function __construct($id, $name, $domain, $active = true) {
        $this->id = $id;
        $this->name = $name;
        $this->domain = $domain;
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

}
