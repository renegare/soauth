<?php

namespace Renegare\Soauth\Controller;

use Renegare\Soauth\LoggerInterface;
use Renegare\Soauth\LoggerTrait;
use Renegare\Soauth\ClientUserProviderTrait;

abstract class AbstractController implements LoggerInterface {
    use LoggerTrait, ClientUserProviderTrait;
}
