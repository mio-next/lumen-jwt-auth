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
use Canis\Lumen\Jwt\Token;
use Canis\Lumen\Jwt\Exceptions\InvalidTokenException;

/**
 * @runTestsInSeparateProcesses
 */
class GuardTest extends BaseTestCase
{

    public function setUp()
    {
        parent::setUp();
    }

    public function testCustomFactory()
    {
        $this->app['config']->set('jwt.adapter', 'Canis\Lumen\Jwt\Adapters\Lcobucci\Factory');
        $guard = $this->getGuard();
        $gen = $this->invoke($guard, 'getGenerator');
        $this->assertTrue($gen instanceof \Canis\Lumen\Jwt\Adapters\Lcobucci\Generator);
    }

    public function testUser()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveById')->andReturn(new Stubs\UserStub());
        $guard = new Guard($provider, $this->getValidTokenRequest());
        $user = $guard->user();
        $this->assertEquals($user->getJWTSubject(), 'user-test-1');
        // check cache
        $provider->shouldReceive('retrieveById')->andReturn(new Stubs\UserBStub());
        $this->assertEquals($guard->user()->getJWTSubject(), 'user-test-1');
    }

    public function testBearerToken()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveById')->andReturn(new Stubs\UserStub());
        $token = $this->getValidToken();
        $guard = new Guard($provider, $this->getValidTokenRequest($token));
        $bearerToken = $guard->getBearerToken();
        $this->assertEquals($bearerToken, (string) $token);
    }

    public function testBadBearerToken()
    {
        $provider = Mockery::mock(UserProvider::class);
        $guard = new Guard($provider, $this->getRequest());
        $bearerToken = $guard->getBearerToken();
        $this->assertFalse($bearerToken);
    }

    public function testBasicToken()
    {
        $provider = Mockery::mock(UserProvider::class);
        $guard = new Guard($provider, $this->getBasicRequest());
        $bearerToken = $guard->getBearerToken();
        $this->assertFalse($bearerToken);
    }

    public function testValidate()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')->andReturn(new Stubs\UserStub());
        $provider->shouldReceive('validateCredentials')->withAnyArgs()->andReturn(true);
        $guard = new Guard($provider, $this->getRequest());
        $this->assertTrue($guard->validate(['user' => 'test', 'password' => 'test']));
    }

    public function testBadValidate()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')->andReturn(new Stubs\UserStub());
        $provider->shouldReceive('validateCredentials')->withAnyArgs()->andReturn(false);
        $guard = new Guard($provider, $this->getRequest());
        $this->assertFalse($guard->validate(['user' => 'test', 'password' => 'test']));
    }

    public function testSetRequest()
    {
        $provider = Mockery::mock(UserProvider::class);
        $guard = new Guard($provider, $this->getRequest());
        $newRequest = $this->getRequest();
        $guard->setRequest($newRequest);
        $this->assertEquals($guard->getRequest(), $newRequest);
    }

    public function testAttempt()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')->andReturn(new Stubs\UserStub());
        $provider->shouldReceive('validateCredentials')->withAnyArgs()->andReturn(true);
        $guard = new Guard($provider, $this->getRequest());
        $token = $guard->attempt(['user' => 'test', 'password' => 'test']);
        $this->assertTrue($token instanceof Token);
    }

    /**
    * @expectedException Canis\Lumen\Jwt\Exceptions\InvalidTokenException
    */
    public function testInvalidTokenAttempt()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')->andReturn(new Stubs\UserStub());
        $provider->shouldReceive('validateCredentials')->withAnyArgs()->andReturn(true);
        config(['jwt.requiredClaims' => ['iss', 'iat', 'exp', 'nbf', 'sub', 'jti', 'boom']]);
        $guard = new Guard($provider, $this->getRequest());
        $token = $guard->attempt(['user' => 'test', 'password' => 'test']);
    }


    public function testBadAttempt()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')->andReturn(new Stubs\UserStub());
        $provider->shouldReceive('validateCredentials')->withAnyArgs()->andReturn(false);
        $guard = new Guard($provider, $this->getRequest());
        $token = $guard->attempt(['user' => 'test', 'password' => 'test']);
        $this->assertFalse($token);
    }

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
