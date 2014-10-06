<?php

namespace Renegare\Soauth;

use Symfony\Component\HttpFoundation\Request;
use Renegare\Soauth\Access\ClientCredentialsAccess;
use Renegare\Soauth\Access\AuthorizationCodeAccess;
use Renegare\Soauth\AccessStorageHandler\AccessStorageHandlerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Renegare\Soauth\Access\Access;

class AccessProvider implements AccessProviderInterface, LoggerInterface {
    use LoggerTrait;

    protected $secret = '';

    /**
     * @param string $secret
     */
    public function __construct($secret = 'ch4ng3Th1s!!!') {
        $this->secret = $secret;
    }

    /**
     * {@inheritdoc}
     */
    public function generateAuthorizationCodeAccess(UserInterface $user, ClientInterface $client) {
        $clientId = $client->getId();
        $username = $user->getUsername();

        $authCode = $this->getDigest(sprintf('ac:ac:%s:%s', $clientId, $username));
        $accessToken = $this->getDigest(sprintf('ac:at:%s:%s', $clientId, $username));
        $refreshToken = $this->getDigest(sprintf('ac:rt:%s:%s', $clientId, $username));

        return new AuthorizationCodeAccess($username, $clientId, $authCode, $accessToken, $refreshToken);
    }

    /**
     * {@inheritdoc}
     */
    public function generateClientCredentialsAccess(ClientInterface $client) {
        $clientId = $client->getId();
        $accessToken = $this->getDigest(sprintf('cc:at:%s', $clientId));
        $refreshToken = $this->getDigest(sprintf('cc:rt:%s', $clientId));
        return new ClientCredentialsAccess($clientId, $accessToken, $refreshToken);
    }

    /**
     * {@inheritdoc}
     */
    public function refreshAccess(Access $access, ClientInterface $client, UserInterface $user = null) {
        if($access instanceOf AuthorizationCodeAccess) {
            $refreshedAccess = $this->generateAuthorizationCodeAccess($user, $client);
        } else if($access instanceOf ClientCredentialsAccess ) {
            throw new \RuntimeException('Hmmm ... needs to be implemented!');
        }

        $refreshedAccess->setPreviousAccess($access);
        return $refreshedAccess;
    }

    /**
     * @todo need to make sure value is as unique as possible
     */
    protected function getDigest($data) {
        $rand = openssl_random_pseudo_bytes(16, $strong);
        return base64_encode(hash_hmac("sha1", $data . bin2hex($rand), $this->secret));
    }
}
