<?php

namespace Renegare\Soauth\Test\Exception;

use Renegare\Soauth\Exception\BadRequestException;
use Renegare\Soauth\Test\WebtestCase;

class BadRequestExceptionTest extends WebtestCase {

    public function testGetRequest() {
        $request = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $e = new BadRequestException($request);
        $this->assertEquals($e->getRequest(), $request);
    }
}
