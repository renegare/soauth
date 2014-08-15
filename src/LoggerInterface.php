<?php

namespace Renegare\Soauth;

use Psr\Log\LoggerInterface as PsrLoggerInterface;
use Psr\Log\LoggerAwareInterface;

interface LoggerInterface extends LoggerAwareInterface, PsrLoggerInterface {}
