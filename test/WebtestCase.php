<?php

namespace Renegare\Soauth\Test;

use Silex\Application;
use Symfony\Component\HttpKernel\Client;
use Symfony\Component\BrowserKit\Cookie;

use Renegare\Soauth\OAuthControllerServiceProvider;

class WebTestCase extends \Silex\WebTestCase {

    private $mockLogger;

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

        $this->configureApplication($app);

        return $app;
    }

    protected function configureApplication(Application $app) {
        $app->register(new \Silex\Provider\ServiceControllerServiceProvider);
        $app->register(new \Silex\Provider\SecurityServiceProvider);

        $provider = new OAuthControllerServiceProvider;
        $app->register($provider);
        $app->mount('/auth', $provider);

        $app['security.firewalls'] = [
            'healthcheck' => [
                'pattern' => '^/healthcheck',
                'anonymous' => true,
                'stateless' => true
            ],

            'auth' => [
                'pattern' => '^/auth',
                'anonymous' => true,
                'stateless' => true
            ],

            'api' => [
                'pattern' => '^/',
                'soauth' => true,
                'stateless' => true
            ]
        ];

        $app->get('/healthcheck', function(){
            return 'All Good!';
        });

        $app->get('/api', function(){
            return 'Access Granted';
        });

        $app['logger'] = $this->getMockLogger();

        // print_r(get_class_methods($this)); die;
    }

    public function getMockLogger() {
        if(!$this->mockLogger) {
            $this->mockLogger = $this->getMock('Psr\Log\LoggerInterface');
        }

        return $this->mockLogger;
    }

    // public function getDataSetName

}
