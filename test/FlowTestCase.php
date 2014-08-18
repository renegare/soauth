<?php

namespace Renegare\Soauth\Test;

use Silex\Application;
use Symfony\Component\HttpFoundation\Response;

class FlowTestCase extends WebtestCase {

    protected $mockRenderer;

    protected function configureApplication(Application $app) {
        parent::configureApplication($app);

        $app['soauth.user.provider.config'] = [
            'test@example.com' => ['password' => $app['security.encoder.digest']->encodePassword('Password123', ''), 'roles' => ['ROLE_USER'], 'enabled' => true]
        ];

        $app['soauth.client.provider.config'] = [
            '1' => [
                'name' => 'Example Client',
                'domain' => 'client.com',
                'active' => true,
                'secret' => 'cl13nt53crt'
            ],
            '2' => [
                'name' => 'Example Client',
                'domain' => 'client.com',
                'active' => false,
                'secret' => 'cl13nt53crt'
            ]
        ];

        $this->configureMocks($app);
    }

    protected function configureMocks(Application $app) {
        $this->mockRenderer = $this->getMock('Renegare\Soauth\RendererInterface');
        $app['soauth.renderer'] = $this->mockRenderer;
        $this->mockRenderer->expects($this->any())
            ->method('renderSignInForm')->will($this->returnCallback(function($data) {
                return '<form method="post">
    <input type="text" name="username" value="'. (isset($data['username'])? $data['username'] : '') .'"/>
    <input type="password" name="password" />
    <input type="hidden" name="redirect_uri" value="'. $data['redirect_uri'] .'" />
    <input type="hidden" name="client_id" value="'. $data['client_id'] .'" />
    <button type="submit">Sign-in</button>
</form>';
            }));
    }
}
