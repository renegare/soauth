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
     * @return Credentials|null if not found or expired
     */
    public function getAuthCodeCredentials($authCode);

    /**
     * Save credentials
     * @param Access $credentials
     * @param int $createdTime
     */
    public function save(Access $credentials, $createdTime = null);

    /**
     * Retrieve credentials using $accessCode
     * @param string $accessCode
     * @return Access|null if not found or expired
     */
    public function getAccessTokenCredentials($accessCode);

    /**
     * Retrieve credentials using $refreshCode
     * @param string $refreshCode
     * @return Access|null if not found or expired
     */
    public function getRefreshTokenCredentials($refreshCode);

    /**
     * invalidate given credentials so it cannot be used anymore
     * @param Credentials $credentials
     */
    public function invalidate(Access $credentials);
}
