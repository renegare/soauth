<?php

namespace Renegare\Soauth;

/**
 * this class handles the persisting and retrieving of non-expired credentials.
 */
interface StorageHandlerInterface {

    /**
     * Retrieve credentials using $authCode
     * @param string $authCode
     * @return CredentialsInterface|null if not found or expired
     */
    public function getAuthCodeCredentials($authCode);

    /**
     * Save credentials
     * @param CredentialsInterface $credentials
     * @param int $createdTime
     */
    public function save(CredentialsInterface $credentials, $createdTime = null);

    /**
     * Retrieve credentials using $accessCode
     * @param string $accessCode
     * @return CredentialsInterface|null if not found or expired
     */
    public function getAccessCodeCredentials($accessCode);

    /**
     * Retrieve credentials using $refreshCode
     * @param string $refreshCode
     * @return CredentialsInterface|null if not found or expired
     */
    public function getRefreshCodeCredentials($refreshCode);

    /**
     * invalidate given credentials so it cannot be used anymore
     * @param CredentialsInterface $credentials
     */
    public function invalidate(CredentialsInterface $credentials);
}
