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
                $this->log[$this->testFullName][] = [
                    'level' => $level,
                    'message' => $message,
                    'context' => $context
                ];
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

            foreach($logs as $log)  {
                $this->writeln(sprintf('[%s] %s %s', $log['level'], $log['message'], json_encode($this->normalize($log['context']))));
            }

            $this->writeln("<<< END: $testName", 3);
        }

        $this->writeln('');

        $this->log = [];

    }

    protected function writeln($string = '', $newLineCount = 1) {
        echo $string . str_repeat("\n", $newLineCount);
    }

    /**
     * credits to Monolog Package (c) Jordi Boggiano <j.boggiano@seld.be>
     */
    protected function normalize($data)
    {
        if (null === $data || is_scalar($data)) {
            return $data;
        }

        if (is_array($data) || $data instanceof \Traversable) {
            $normalized = array();

            $count = 1;
            foreach ($data as $key => $value) {
                if ($count++ >= 1000) {
                    $normalized['...'] = 'Over 1000 items, aborting normalization';
                    break;
                }
                $normalized[$key] = $this->normalize($value);
            }

            return $normalized;
        }

        if ($data instanceof \DateTime) {
            return $data->format($this->dateFormat);
        }

        if (is_object($data)) {
            if ($data instanceof Exception) {
                return $this->normalizeException($data);
            }

            return sprintf("[object] (%s: %s)", get_class($data), $this->toJson($data, true));
        }

        if (is_resource($data)) {
            return '[resource]';
        }

        return '[unknown('.gettype($data).')]';
    }

    protected function normalizeException(Exception $e)
    {
        $data = array(
            'class' => get_class($e),
            'message' => $e->getMessage(),
            'file' => $e->getFile().':'.$e->getLine(),
        );

        $trace = $e->getTrace();
        foreach ($trace as $frame) {
            if (isset($frame['file'])) {
                $data['trace'][] = $frame['file'].':'.$frame['line'];
            } else {
                $data['trace'][] = json_encode($frame);
            }
        }

        if ($previous = $e->getPrevious()) {
            $data['previous'] = $this->normalizeException($previous);
        }

        return $data;
    }

    protected function toJson($data, $ignoreErrors = false)
    {
        // suppress json_encode errors since it's twitchy with some inputs
        if ($ignoreErrors) {
            if (version_compare(PHP_VERSION, '5.4.0', '>=')) {
                return @json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            }

            return @json_encode($data);
        }

        if (version_compare(PHP_VERSION, '5.4.0', '>=')) {
            return json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }

        return json_encode($data);
    }

}
