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
     * @return boolean|string   False if auth failed or the name of the guard used
     */
    public function universalUserLogin(AuthFactory $auth);


    /**
     * Refresh a token
     *
     * @param  AuthFactory     $auth
     * @return boolean|Token   False if auth failed or the new token
     */
    public function refresh(AuthFactory $auth);

    /**
     * Get's the bearer token from the request header
     * 
     * @return Token|boolean
     */
    public function getBearerToken($isRefresh = false);
}
