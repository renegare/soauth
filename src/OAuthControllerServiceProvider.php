<?php

namespace Renegare\Soauth;

use Silex\ControllerProviderInterface;
use Silex\Application;
use Silex\ServiceProviderInterface;

class OAuthControllerServiceProvider implements ControllerProviderInterface, ServiceProviderInterface {

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

        $app['soauth.access.provider'] = $app->share(function(Application $app){
            $accessProvider = new AccessProvider($app['soauth.access.storage.handler'], $app['soauth.access.client.provider'], $app['soauth.access.user.provider']);

            if(isset($app['logger']) && $app['logger']) {
                $accessProvider->setLogger($app['logger']);
            }

            return $accessProvider;
        });

        $app['soauth.access.storage.handler'] = $app->share(function(Application $app){
            return new AccessStorageHandler();
        });

        $app['soauth.access.client.provider'] = $app->share(function(Application $app){
            return new AccessClientProvider();
        });

        $app['soauth.access.user.provider'] = $app->share(function(Application $app){
            return new AccessUserProvider();
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
