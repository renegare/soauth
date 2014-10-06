<?php

namespace Renegare\Soauth\Test\Access;

use Renegare\Soauth\Access\Access;
use Renegare\Soauth\Test\WebTestCase;

class AccessTest extends WebTestCase {

    public function testGetPreviousAccess() {
        $access = new Access('...', '...');
        $prevAccess = new Access('...', '...');

        $this->assertNotSame($access, $prevAccess);
        $access->setPreviousAccess($prevAccess);
        $this->assertSame($prevAccess, $access->getPreviousAccess());
    }
}
