# SOAuth - Simple Silex OAuth2 Provider

[![Build Status](https://travis-ci.org/renegare/soauth.png?branch=master)](https://travis-ci.org/renegare/soauth)

currently only supports the following flows:

* Authorization Code
* Refresh Code

## Requirements

* PHP 5.4
* composer (preferably latest)

## Installation

```
$ composer require renegare/aiv:dev-master
```

## Usage

There is no documentation other than the tests. Please take a look in ```/test``` direcotory or read the source
code.

## Test

Check out the repo and from the top level directory run the
following command (xdebug required for coverage):

```
$ composer update && composer test -- --coverage-text
```

## Road Map

### Phase 1 (v0.0.1)

* Access Provider - refresh flow not done // Done
* Refactor ... a lot of things are prefixed with 'Access' ... remove it // Done
* Access Controller needs to expect+verify client secret // Done
* Fix any subsequent bugs from the wild!?

### Phase 2 (v0.1)

* Refactor so symfony/security and silex/silex is an optional dependency
* Auth Controller needs to be refactored to handle multiple authentication flows (make it extendable?)
* Invalidate end point ... ?

### Phase 3 (v1.0)

* Implement outstanding official flows

### Phase 4 (v1.0.x)

* Implement auth flow that handles/proxies authentication via social platforms ... is that even possible?!
