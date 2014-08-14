<?php

namespace Renegare\Soauth\Test;

use Renegare\Soauth\BadRequestException;

class BadRequestExceptionTest extends WebtestCase {

    public function testGetRequest() {
        $request = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $e = new BadRequestException($request);
        $this->assertEquals($e->getRequest(), $request);
    }
}
