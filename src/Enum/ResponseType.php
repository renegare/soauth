<?php

namespace Renegare\Soauth\Enum;

class ResponseType {
    const CODE = 'code';

    /**
     * @return boolean
     */
    public static function isSupported($type) {
        return in_array($type, [ResponseType::CODE]);
    }
}
