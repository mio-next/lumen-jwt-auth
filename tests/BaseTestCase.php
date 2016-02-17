<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace CanisUnit\Lumen\Jwt;

use Auth;
use Canis\Lumen\Jwt\Adapters\Lcobucci\Generator;
use Canis\Lumen\Jwt\ServiceProvider as JwtServiceProvider;

abstract class BaseTestCase extends \Laravel\Lumen\Testing\TestCase
{
    public function createApplication()
    {
        $app = new \Laravel\Lumen\Application(__DIR__);
        $app->withFacades();
        $app->register(JwtServiceProvider::class);
        return $app;
    }

    public function getGuard()
    {
        return Auth::guard('jwt');
    }

    protected function getJwtConfig($config = [])
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
        $generator = new Generator($this->getJwtConfig($config));
        return $generator(['sub' => 'test']);
    }

    protected function getExpiredToken()
    {
        $generator = new Generator($this->getJwtConfig(['expOffset' => -1]));
        return $generator(['sub' => 'test']);
    }

    protected function getNotReadyToken()
    {
        $generator = new Generator($this->getJwtConfig(['nbfOffset' => 3600]));
        return $generator(['sub' => 'test']);
    }

    protected function invoke($object, $method, array $args = [])
    {
        $classReflection = new \ReflectionClass(get_class($object));
        $methodReflection = $classReflection->getMethod($method);
        $methodReflection->setAccessible(true);
        $result = $methodReflection->invokeArgs($object, $args);
        $methodReflection->setAccessible(false);
        return $result;
    }

    
}
