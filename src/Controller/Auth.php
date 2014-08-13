<?php

namespace Renegare\Soauth\Controller;

use Renegare\Soauth\RendererInterface;

class Auth {

    protected $renderer;

    public function setRenderer(RendererInterface $renderer) {
        $this->renderer = $renderer;
    }

    public function signinAction() {
        $data = [];
        return $this->renderer->renderSignInForm($data);
    }
}
