<?php

namespace Renegare\Soauth\Test;

use Psr\Log\LogLevel;

class AbstractLoggerTest extends WebtestCase {

    public function testLog() {
        $logger = $this->getMock('Psr\Log\LoggerInterface');
        $logger->expects($this->once())->method('log')
            ->will($this->returnCallback(function($level, $message, $context) {
                $this->assertEquals('logging something', $message);
                $this->assertEquals(['...'], $context);
                $this->assertEquals(LogLevel::INFO, $level);
            }));
        $abstractLogger = $this->getMockForAbstractClass('Renegare\Soauth\AbstractLogger');
        $abstractLogger->setLogger($logger);
        $abstractLogger->info('logging something', ['...']);
    }
}
