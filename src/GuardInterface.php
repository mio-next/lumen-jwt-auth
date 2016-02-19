<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt;

use Illuminate\Contracts\Auth\Factory as AuthFactory;

interface GuardInterface
{
    /**
     * Log in with bearer token from any guard
     * @param  AuthFactory      $auth
     * @param  array            $claimValidation
     * @return boolean|string   False if auth failed or the name of the guard used
     */
    public function universalUserLogin(AuthFactory $auth, $claimValidation = []);
}
