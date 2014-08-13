<?php

namespace Renegare\Soauth;

use Silex\ControllerProviderInterface;
use Silex\Application;

class OAuthControllerProvider implements ControllerProviderInterface {

    function connect(Application $app) {
        $controllers = $app['controllers_factory'];

        $app['soauth.controller.auth'] = $app->share(function($app){
            $controller = new Controller\Auth;
            $controller->setRenderer($app['soauth.renderer']);
            $controller->setClientProvider($app['soauth.client.provider']);
            $controller->setUserProvider($app['soauth.user.provider']);
            $controller->setAccessProvider($app['soauth.access.provider']);
            return $controller;
        });

        $controllers->get('auth', 'soauth.controller.auth:signinAction');
        $controllers->post('auth', 'soauth.controller.auth:authenticateAction');

        return $controllers;
    }

}
