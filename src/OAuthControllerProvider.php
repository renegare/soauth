<?php

namespace Renegare\Soauth;

use Silex\ControllerProviderInterface;
use Silex\Application;
use Silex\ServiceProviderInterface;

class OAuthControllerProvider implements ControllerProviderInterface, ServiceProviderInterface {

    public function register(Application $app) {
        $app['security.authentication_listener.factory.soauth'] = $app->protect(function ($name, $options) use ($app) {

            $app['security.authentication_provider.'.$name.'.soauth'] = $app->share(function () use ($app, $name) {
                return null;
            });

            $app['security.authentication_listener.'.$name.'.soauth'] = $app->share(function () use ($app, $name) {

                $listener = new Listener($name, $app['security'], $app['soauth.access.provider']);

                if(isset($app['logger']) && $app['logger']) {
                    $listener->setLogger($app['logger']);
                }

                return $listener;
            });

            return array(
                // the authentication provider id
                'security.authentication_provider.'.$name.'.soauth',
                // the authentication listener id
                'security.authentication_listener.'.$name.'.soauth',
                // the entry point id
                null,
                // the position of the listener in the stack
                'pre_auth'
            );
        });
    }

    public function boot(Application $app) {}

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

        $controllers->get('/', 'soauth.controller.auth:signinAction');
        $controllers->post('/', 'soauth.controller.auth:authenticateAction');

        $controllers->post('/access', 'soauth.controller.access:exchangeAction');
        $controllers->put('/access', 'soauth.controller.access:refreshAction');

        return $controllers;
    }

}
