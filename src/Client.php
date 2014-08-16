<?php

namespace Renegare\Soauth;

class Client implements ClientInterface {
    protected $id;
    protected $name;

    /**
     * @param string|integer $id
     * @param string $name
     */
    public function __construct($id, $name) {
        $this->id = $id;
        $this->name = $name;
    }

    /**
     * {@inheritdoc}
     */
    public function getId() {
        return $this->id;
    }

    /**
     * get client name
     * @return string
     */
    public function getName() {
        return $this->id;
    }
}
