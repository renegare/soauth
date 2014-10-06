<?php

namespace Renegare\Soauth;

use Silex\ControllerProviderInterface;
use Silex\Application;
use Silex\ServiceProviderInterface;

class OAuthControllerServiceProvider implements ControllerProviderInterface, ServiceProviderInterface {

    public function register(Application $app) {
        $app['soauth.test'] = false;

        $app['security.authentication_listener.factory.soauth'] = $app->protect(function ($name, $options) use ($app) {
            $app['security.authentication_provider.'.$name.'.soauth'] = $app->share(function () use ($app, $name) {
                return null;
            });

            if(!isset($app['security.authentication_listener.'.$name.'.soauth'])) {
                $app['security.authentication_listener.'.$name.'.soauth'] = $app->share(function () use ($app, $name) {

                    $listener = new Listener($name, $app['security'], $app['soauth.auth.provider'], $app['soauth.storage.handler']);

                    $listener->setUserProvider($app['soauth.user.provider']);
                    $listener->setClientProvider($app['soauth.client.provider']);

                    if(isset($app['logger']) && $app['logger']) {
                        $listener->setLogger($app['logger']);
                    }

                    return $listener;
                });
            }

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
            $accessProvider = new AccessProvider;

            if(isset($app['logger']) && $app['logger']) {
                $accessProvider->setLogger($app['logger']);
            }

            return $accessProvider;
        });

        $app['soauth.storage.handler.mock'] = $app->share(function(Application $app){
            return new AccessStorageHandler\MockAccessStorageHandler();
        });

        $app['soauth.storage.handler'] = $app->share(function(Application $app) {
            if($app['soauth.test']) {
                return $app['soauth.storage.handler.mock'];
            }

            throw \RuntimeException("No 'soauth.storage.handler' service configured!");
        });

        $app['soauth.client.provider'] = $app->share(function(Application $app){
            return new ClientProvider($app['soauth.client.provider.config']);
        });

        $app['soauth.user.provider'] = $app->share(function(Application $app){
            return new UserProvider($app['soauth.user.provider.config']);
        });

        $app['soauth.auth.provider'] = $app->share(function(Application $app) {
            return new AuthorizationProvider\BearerAuthorizationProvider();
        });

        $app['soauth.user.provider.config'] = [];
        $app['soauth.client.provider.config'] = [];
    }

    public function boot(Application $app) {}

    function connect(Application $app) {
        $controllers = $app['controllers_factory'];

        $app['soauth.controller.token'] = $app->share(function($app){
            $controller = new Controller\TokenController($app['soauth.access.provider'], $app['soauth.storage.handler'], $app['soauth.auth.provider']);

            $controller->setUserProvider($app['soauth.user.provider']);
            $controller->setClientProvider($app['soauth.client.provider']);

            if(isset($app['logger']) && $app['logger']) {
                $controller->setLogger($app['logger']);
            }

            return $controller;
        });

        $app['soauth.controller.auth'] = $app->share(function($app){
            $controller = new Controller\AuthController(
                $app['soauth.renderer'],
                $app['soauth.access.provider'],
                $app['soauth.storage.handler']
            );

            $controller->setUserProvider($app['soauth.user.provider']);
            $controller->setClientProvider($app['soauth.client.provider']);

            if(isset($app['logger']) && $app['logger']) {
                $controller->setLogger($app['logger']);
            }

            return $controller;
        });

        // main entry point for tokens
        $controllers->post('/token', 'soauth.controller.token:grantAction');

        // authorization flow
        $controllers->get('/auth', 'soauth.controller.auth:signinAction');
        $controllers->post('/auth', 'soauth.controller.auth:authenticateAction');


        return $controllers;
    }

}
