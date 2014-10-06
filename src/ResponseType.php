<?php

namespace Renegare\Soauth;

class ResponseType {
    const CODE = 'code';

    /**
     * @return boolean
     */
    public static function isSupported($type) {
        return in_array($type, [ResponseType::CODE]);
    }
}
