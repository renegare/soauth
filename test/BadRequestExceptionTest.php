<?php

namespace Renegare\Soauth\Test;

use Renegare\Soauth\Test\WebTestCase;
use Renegare\Soauth\BadRequestException;

class BadRequestExceptionTest extends WebtestCase {

    public function testGetErrors() {
        $e = new BadRequestException('', ['...']);
        $this->assertEquals(['...'], $e->getErrors());
    }
}
