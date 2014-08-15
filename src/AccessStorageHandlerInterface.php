<?php

namespace Renegare\Soauth;

/**
 * this class handles the persisting and retrieving of non-expired credentials.
 */
interface AccessStorageHandlerInterface {

    /**
     * Retrieve credentials using $authCode
     * @param string $authCode
     * @return CredentialsInterface|null if not found or expired
     */
    public function getAuthCodeCredentials($authCode);

    /**
     * Save credentials
     * @param CredentialsInterface $credentials
     */
    public function save(CredentialsInterface $credentials);
}
