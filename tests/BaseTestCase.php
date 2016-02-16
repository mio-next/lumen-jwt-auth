<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace CanisUnit\Lumen\Jwt;

use Canis\Lumen\Jwt\JwtGenerator;

abstract class BaseTestCase extends \PHPUnit_Framework_TestCase
{
    protected function getConfig($config = [])
    {
        return array_merge([
            'issuer' => 'http://test.com',
            'secret' => 'super-secret-test',
            'expOffset' => 3600,
            'requiredClaims' => ['iss', 'iat', 'exp', 'nbf', 'sub', 'jti']
        ], $config);
    }

    protected function getValidToken($config = [])
    {
        $generator = new JwtGenerator($this->getConfig($config));
        return $generator(['sub' => 'test']);
    }

    protected function getExpiredToken()
    {
        $generator = new JwtGenerator($this->getConfig(['expOffset' => -1]));
        return $generator(['sub' => 'test']);
    }

    protected function getNotReadyToken()
    {
        $generator = new JwtGenerator($this->getConfig(['nbfOffset' => 3600]));
        return $generator(['sub' => 'test']);
    }
}
