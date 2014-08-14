<?php

namespace Renegare\Soauth;

use Psr\Log\LoggerInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerTrait;
use Psr\Log\LoggerAwareTrait;

abstract class AbstractController implements LoggerAwareInterface, LoggerInterface {
    use LoggerTrait, LoggerAwareTrait;

    /**
     * {@inheritdoc}
     */
    public function log($level, $message, array $context = array()) {
        if($this->logger) {
            $this->logger->log($level, $message, $context);
        }
    }
}
