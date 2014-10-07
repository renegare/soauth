<?php

namespace Renegare\Soauth\Controller;

use Renegare\Soauth\Log\LoggerInterface;
use Renegare\Soauth\Log\LoggerTrait;
use Renegare\Soauth\ClientUserProviderTrait;

abstract class AbstractController implements LoggerInterface {
    use LoggerTrait, ClientUserProviderTrait;
}
