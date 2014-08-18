<?php

namespace Renegare\Soauth;

interface RendererInterface {

    /**
     * render entry point response for authentication
     * @param array $data - contains
     * * client => Clientinterface
     * * client_id => string
     * * redirect_uri => string
     * * username => string (not always present)
     * @return string
     */
    public function renderSignInForm(array $data = []);
}
