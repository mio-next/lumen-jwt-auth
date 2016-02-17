<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace CanisUnit\Lumen\Jwt;

use Mockery;
use Auth;
use Canis\Lumen\Jwt\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Canis\Lumen\Jwt\Exceptions\InvalidTokenException;

/**
 * @runTestsInSeparateProcesses
 */
class GuardTest extends BaseTestCase
{

    public function testCustomFactory()
    {
        $this->app['config']->set('jwt.adapter', 'Canis\Lumen\Jwt\Adapters\Lcobucci\Factory');
        $guard = $this->getGuard();
        $gen = $this->invoke($guard, 'getGenerator');
        $this->assertTrue($gen instanceof \Canis\Lumen\Jwt\Adapters\Lcobucci\Generator);
    }

    // public function testUser()
    // {
    //     $provider = Mockery::mock(UserProvider::class);
    //     $provider->shouldReceive('retrieveById')->andReturn(new Stubs\UserStub());

    //     $guard = Mockery::mock($this->getGuard());
    //     $guard->shouldReceive('getBearerToken')->andReturn('ddddd');
    //     $guard->shouldReceive('getProvider')->andReturn($provider);
    //     $user = $guard->user();
    //     $this->assertEquals($user->getJWTSubject(), 'user-test-1');
    // }

    /**
    * @expectedException Canis\Lumen\Jwt\Exceptions\InvalidAdapterException
    */
    public function testUnknownFactory()
    {
        $this->app['config']->set('jwt.adapter', 'boom');
        $guard = $this->getGuard();
        $gen = $this->invoke($guard, 'getGenerator');
    }

    public function testGetGenerator()
    {
        $guard = $this->getGuard();
        $gen = $this->invoke($guard, 'getGenerator');
        $this->assertTrue($gen instanceof \Canis\Lumen\Jwt\Contracts\Generator);
        $proc = $this->invoke($guard, 'getProcessor');
        $this->assertTrue($proc instanceof \Canis\Lumen\Jwt\Contracts\Processor);
    }
}
