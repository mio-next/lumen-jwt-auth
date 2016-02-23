<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace CanisUnit\Lumen\Jwt;

use Auth;
use Illuminate\Http\Request;
use Canis\Lumen\Jwt\Adapters\Lcobucci\Generator;
use Canis\Lumen\Jwt\Adapters\Lcobucci\Factory;
use Canis\Lumen\Jwt\ServiceProvider as JwtServiceProvider;
use Canis\Lumen\Jwt\Guard as JwtGuard;
use Illuminate\Support\Facades\Facade;

abstract class BaseTestCase extends \Laravel\Lumen\Testing\TestCase
{
    public function createApplication()
    {
        Facade::clearResolvedInstances();
        $app = new \Laravel\Lumen\Application(__DIR__);
        $app->withFacades();
        $app->register(JwtServiceProvider::class);
        return $app;
    }

    public function getValidTokenRequest($token = null)
    {
        if ($token === null) {
            $token = $this->getValidToken();
        }
        $server = ['HTTP_AUTHORIZATION' => 'Bearer ' . (string) $token];
        return Request::create('/foo', 'GET', [], [], [], $server);
    }

    public function getBasicRequest()
    {
        $server = ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('username:password')];
        return Request::create('/foo', 'GET', [], [], [], $server);
    }

    public function getRequest()
    {
        return Request::create('/foo', 'GET');
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
            'refreshOffsetAllowance' => 4000,
            'jtiInHeader' => false,
            'requiredClaims' => ['iss', 'iat', 'exp', 'nbf', 'sub', 'jti']
        ], $config);
    }

    protected function getValidToken($config = [], $claims = [])
    {
        $factory = new Factory($this->getJwtConfig($config));
        $generator = $factory->getGenerator();
        return $generator(array_merge(['sub' => 'test', JwtGuard::JWT_GUARD_CLAIM => 'jwt'], $claims));
    }

    protected function getExpiredToken($offset = -1)
    {
        $factory = new Factory($this->getJwtConfig(['expOffset' => $offset]));
        $generator = $factory->getGenerator();
        return $generator(['sub' => 'test', JwtGuard::JWT_GUARD_CLAIM => 'jwt']);
    }
    
    protected function getNotReadyToken()
    {
        $factory = new Factory($this->getJwtConfig(['nbfOffset' => 3600]));
        $generator = $factory->getGenerator();
        return $generator(['sub' => 'test', JwtGuard::JWT_GUARD_CLAIM => 'jwt']);
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

    protected function privateProperty($object, $property)
    {
        $classReflection = new \ReflectionClass(get_class($object));
        $propertyReflection = $classReflection->getProperty($property);
        $propertyReflection->setAccessible(true);
        $result = $propertyReflection->getValue($object);
        $propertyReflection->setAccessible(false);
        return $result;
    }

}
