<?php

namespace Renegare\Soauth;

use Psr\Log\LoggerTrait as PsrLoggerTrait;
use Psr\Log\LoggerAwareTrait;

trait LoggerTrait {
    use PsrLoggerTrait, LoggerAwareTrait;

    /**
     * {@inheritdoc}
     */
    public function log($level, $message, array $context = array()) {
        if($this->logger) {
            $this->logger->log($level, $message, $context);
        }
    }
}
