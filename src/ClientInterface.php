<?php

namespace Renegare\Soauth;

interface ClientInterface {
    /**
     * return the client identifier
     * @return mixed
     */
    public function getId();

    public function getName();

    public function isActive();

    public function getDomain();

}
