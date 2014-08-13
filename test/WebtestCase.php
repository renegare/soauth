<?php

namespace Renegare\Soauth\Test;

use Silex\Application;
use Symfony\Component\HttpKernel\Client;
use Symfony\Component\BrowserKit\Cookie;

class WebTestCase extends \Silex\WebTestCase {

    public function createClient(array $server = [], Application $app=null)
    {
        if(!$app) {
            $app = $this->createApplication();
        }
        return new Client($app, $server);
    }

    public function createApplication($disableExceptionHandler = false)
    {
        $app = new Application();

        if($disableExceptionHandler) {
            $app['exception_handler']->disable();
        }

        return $app;
    }

}
