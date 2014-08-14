<?php

namespace Renegare\Soauth;

use Silex\ControllerProviderInterface;
use Silex\Application;

class OAuthControllerProvider implements ControllerProviderInterface {

    function connect(Application $app) {
        $controllers = $app['controllers_factory'];

        $app['soauth.controller.auth'] = $app->share(function($app){
            $controller = new Controller\Auth;

            if(isset($app['logger']) && $app['logger']) {
                $controller->setLogger($app['logger']);
            }

            $controller->setRenderer($app['soauth.renderer']);
            $controller->setClientProvider($app['soauth.client.provider']);
            $controller->setUserProvider($app['soauth.user.provider']);
            $controller->setAccessProvider($app['soauth.access.provider']);

            return $controller;
        });

        $app['soauth.controller.access'] = $app->share(function($app){
            $controller = new Controller\Access;

            if(isset($app['logger']) && $app['logger']) {
                $controller->setLogger($app['logger']);
            }

            $controller->setAccessProvider($app['soauth.access.provider']);

            return $controller;
        });

        $controllers->get('', 'soauth.controller.auth:signinAction');
        $controllers->post('', 'soauth.controller.auth:authenticateAction');

        $controllers->post('access', 'soauth.controller.access:exchangeAction');
        $controllers->put('access', 'soauth.controller.access:refreshAction');

        return $controllers;
    }

}
