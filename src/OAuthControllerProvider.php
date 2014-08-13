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
            return $controller;
        });

        $controllers->get('auth', 'soauth.controller.auth:signinAction');

        return $controllers;
    }

}
