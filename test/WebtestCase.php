<?php

namespace Renegare\Soauth\Test;

use Silex\Application;
use Symfony\Component\HttpKernel\Client;
use Symfony\Component\BrowserKit\Cookie;

use Renegare\Soauth\OAuthControllerProvider;
use Silex\Provider\ServiceControllerServiceProvider;

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
        $app['debug'] = true;

        $app->register(new ServiceControllerServiceProvider); // needs to be registered!!

        $app->mount('/', new OAuthControllerProvider);

        return $app;
    }

}
