<?php

namespace Renegare\Soauth\Enum;

class GrantType {
    const AUTHORIZATION_CODE = 'authorization_code';
    const CLIENT_CREDENTIALS = 'client_credentials';
    const REFRESH_TOKEN = 'refresh_token';

    /**
     * @return boolean
     */
    public static function isSupported($type) {
        return in_array($type, [
            GrantType::AUTHORIZATION_CODE,
            GrantType::CLIENT_CREDENTIALS,
            GrantType::REFRESH_TOKEN]);
    }
}
