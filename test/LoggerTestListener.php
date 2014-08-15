<?php

namespace Renegare\Soauth\Test;

class LoggerTestListener extends \PHPUnit_Framework_BaseTestListener {
    protected $mockLogger;
    protected $log;
    protected $testFullName;

    /**
     * {@inheritdoc}
     */
    public function addError(\PHPUnit_Framework_Test $test, \Exception $e, $time) {
        $this->error = true;
    }

    /**
     * {@inheritdoc}
     */
    public function addFailure(\PHPUnit_Framework_Test $test, \PHPUnit_Framework_AssertionFailedError $e, $time) {
        $this->error = true;
    }

    /**
     * {@inheritdoc}
     */
    public function addIncompleteTest(\PHPUnit_Framework_Test $test, \Exception $e, $time) {}

    /**
     * {@inheritdoc}
     */
    public function addRiskyTest(\PHPUnit_Framework_Test $test, \Exception $e, $time) {}

    /**
     * {@inheritdoc}
     */
    public function addSkippedTest(\PHPUnit_Framework_Test $test, \Exception $e, $time) {}

    /**
     * {@inheritdoc}
     */
    public function startTestSuite(\PHPUnit_Framework_TestSuite $suite) {}

    /**
     * {@inheritdoc}
     */
    public function endTestSuite(\PHPUnit_Framework_TestSuite $suite) {

    }

    /**
     * {@inheritdoc}
     */
    public function startTest(\PHPUnit_Framework_Test $test) {
        // print_r(get_class_methods($test)); die;
        $this->error = false;
        $this->mockLogger = $test->getMockLogger();
        $this->testFullName = sprintf('%s::%s', get_class($test), $test->getName());
        $this->mockLogger->expects($test->any())->method('log')
            ->will($test->returnCallback(function($level, $message, $context){
                $this->log[$this->testFullName][] = sprintf('[%s] %s', strtoupper($level), $message);
            }));
    }

    /**
     * {@inheritdoc}
     */
    public function endTest(\PHPUnit_Framework_Test $test, $time) {
        if(!$this->error) {
            unset($this->log[$this->testFullName]);
        }
    }

    public function __destruct() {

        if(!count($this->log)) return;

        $this->writeln('', 2);
        $this->writeln("======================================");
        $this->writeln("Printing out log for failed tests ...");
        $this->writeln("======================================", 2);

        foreach($this->log as $testName => $logs) {
            $this->writeln(">>> START: $testName", 2);
            $this->writeln(implode("\n", $logs), 2);
            $this->writeln("<<< END: $testName", 3);
        }

        $this->writeln('');

        $this->log = [];

    }

    protected function writeln($string = '', $newLineCount = 1) {
        echo $string . str_repeat("\n", $newLineCount);
    }
}
