<?php

namespace Renegare\Soauth;

interface ClientInterface {

    /**
     * return the client identifier
     * @return mixed
     */
    public function getId();

    /**
     * get client name
     * @return string
     */
    public function getName();

    /**
     * get client active state name
     * @return boolean
     */
    public function isActive();

    /**
     * get client domain name
     * @return string
     */
    public function getDomain();

    /**
     * get client secret
     * @return string
     */
    public function getSecret();

}
