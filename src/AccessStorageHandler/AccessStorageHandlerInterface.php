<?php

namespace Renegare\Soauth\AccessStorageHandler;

use Renegare\Soauth\Access\Access;

/**
 * this class handles the persisting and retrieving of non-expired credentials.
 */
interface AccessStorageHandlerInterface {

    /**
     * Retrieve credentials using $authCode
     * @param string $authCode
     * @return AuthorizationCodeAccess|null if not found or expired
     */
    public function getAuthorizationCodeAccess($authCode);

    /**
     * Save credentials
     * @param Access $access
     * @param int $createdTime
     */
    public function save(Access $access, $createdTime = null);

    /**
     * Retrieve credentials using $accessCode
     * @param string $accessToken
     * @return Access|null if not found or expired
     */
    public function getAccess($accessToken);

    /**
     * Retrieve credentials using $refreshCode
     * @param string $refreshToken
     * @return Access|null if not found or expired
     */
    public function getRefreshTokenAccess($refreshToken);

    /**
     * invalidate given credentials so it cannot be used anymore
     * @param Access $access
     */
    public function invalidate(Access $access);
}
