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
use Illuminate\Contracts\Auth\Factory as AuthFactory;
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
        $guard = new Guard('jwt', $provider, $this->getValidTokenRequest());
        $user = $guard->user();
        $this->assertEquals($user->getJWTSubject(), 'user-test-1');
        // check cache
        $provider->shouldReceive('retrieveById')->andReturn(new Stubs\UserBStub());
        $this->assertEquals($guard->user()->getJWTSubject(), 'user-test-1');
    }

    public function testForeignUserFail()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveById')->andReturn(new Stubs\UserStub());
        $guard = new Guard('jwt-alt', $provider, $this->getValidTokenRequest());
        $user = $guard->user();
        $this->assertNull($user);
    }

    public function testUniversalUserSelf()
    {
        $token = $this->getValidToken([], [Guard::JWT_GUARD_CLAIM => 'jwt']);
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveById')->andReturn(new Stubs\UserStub());
        $guard = new Guard('jwt', $provider, $this->getValidTokenRequest($token));
        $guardAlt = new Guard('jwt-alt', $provider, $this->getValidTokenRequest($token));
        $auth = Mockery::mock(AuthFactory::class);
        $auth->shouldReceive('guard')->with('jwt-alt')->andReturn($guardAlt);
        $auth->shouldReceive('guard')->with('jwt')->andReturn($guard);

        $guardId = $guard->universalUserLogin($auth);

        $this->assertEquals('jwt', $guardId);
        $user = $guard->user();
        $this->assertEquals($user->getJWTSubject(), 'user-test-1');
    }


    public function testUniversalUserForeign()
    {
        $token = $this->getValidToken([], [Guard::JWT_GUARD_CLAIM => 'jwt-alt']);
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveById')->andReturn(new Stubs\UserStub());
        $guard = new Guard('jwt', $provider, $this->getValidTokenRequest($token));
        $guardAlt = new Guard('jwt-alt', $provider, $this->getValidTokenRequest($token));
        $auth = Mockery::mock(AuthFactory::class);
        $auth->shouldReceive('guard')->with('jwt-alt')->andReturn($guardAlt);
        $auth->shouldReceive('guard')->with('jwt')->andReturn($guard);
        $guardId = $guard->universalUserLogin($auth);
        $this->assertEquals('jwt-alt', $guardId);
        $user = $guardAlt->user();
        $this->assertEquals($user->getJWTSubject(), 'user-test-1');
    }


    public function testUniversalUserUnknown()
    {
        $token = $this->getValidToken([], [Guard::JWT_GUARD_CLAIM => 'jwt-alt']);
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveById')->andReturn(null);
        $guard = new Guard('jwt', $provider, $this->getValidTokenRequest($token));
        $guardAlt = new Guard('jwt-alt', $provider, $this->getValidTokenRequest($token));
        $auth = Mockery::mock(AuthFactory::class);
        $auth->shouldReceive('guard')->with('jwt-alt')->andReturn($guardAlt);
        $auth->shouldReceive('guard')->with('jwt')->andReturn($guard);
        $guardId = $guard->universalUserLogin($auth);
        $this->assertEquals(false, $guardId);
    }

    public function testBearerToken()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveById')->andReturn(new Stubs\UserStub());
        $token = $this->getValidToken();
        $guard = new Guard('jwt', $provider, $this->getValidTokenRequest($token));
        $bearerToken = $guard->getBearerToken();
        $this->assertEquals((string) $token, $bearerToken);
    }


    public function testRefreshOkay()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveById')->andReturn(new Stubs\UserStub());
        $token = $this->getValidToken([], ['sub' => 'user-test-1']);
        $guard = new Guard('jwt', $provider, $this->getValidTokenRequest($token));

        $auth = Mockery::mock(AuthFactory::class);
        $auth->shouldReceive('guard')->with('jwt')->andReturn($guard);

        $newToken = $guard->refresh($auth);
        $this->assertEquals($token->getClaim('sub'), $newToken->getClaim('sub'));
    }


    public function testRefreshExpired()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveById')->andReturn(new Stubs\UserStub());
        $token = $this->getValidToken([], ['sub' => 'user-test-1', 'exp' => time()-1]);
        $guard = new Guard('jwt', $provider, $this->getValidTokenRequest($token));

        $auth = Mockery::mock(AuthFactory::class);
        $auth->shouldReceive('guard')->with('jwt')->andReturn($guard);

        $newToken = $guard->refresh($auth);
        $this->assertEquals($token->getClaim('sub'), $newToken->getClaim('sub'));
    }


    public function testRefreshTooOld()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveById')->andReturn(new Stubs\UserStub());
        $token = $this->getValidToken([], ['sub' => 'user-test-1', 'exp' => time()-4100]);
        $guard = new Guard('jwt', $provider, $this->getValidTokenRequest($token));

        $auth = Mockery::mock(AuthFactory::class);
        $auth->shouldReceive('guard')->with('jwt')->andReturn($guard);

        $newToken = $guard->refresh($auth);
        $this->assertFalse($newToken);
    }

    public function testRefreshNotValid()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveById')->andReturn(new Stubs\NeedyUserStub());
        $token = $this->getValidToken([], ['sub' => 'user-test-1']);
        $guard = new Guard('jwt', $provider, $this->getValidTokenRequest($token));

        $auth = Mockery::mock(AuthFactory::class);
        $auth->shouldReceive('guard')->with('jwt')->andReturn($guard);

        $newToken = $guard->refresh($auth);
        $this->assertFalse($newToken);
    }

    public function testBadBearerToken()
    {
        $provider = Mockery::mock(UserProvider::class);
        $guard = new Guard('jwt', $provider, $this->getRequest());
        $bearerToken = $guard->getBearerToken();
        $this->assertFalse($bearerToken);
    }

    public function testBasicToken()
    {
        $provider = Mockery::mock(UserProvider::class);
        $guard = new Guard('jwt', $provider, $this->getBasicRequest());
        $bearerToken = $guard->getBearerToken();
        $this->assertFalse($bearerToken);
    }

    public function testValidate()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')->andReturn(new Stubs\UserStub());
        $provider->shouldReceive('validateCredentials')->withAnyArgs()->andReturn(true);
        $guard = new Guard('jwt', $provider, $this->getRequest());
        $this->assertTrue($guard->validate(['user' => 'test', 'password' => 'test']));
    }


    public function testBadValidate()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')->andReturn(new Stubs\UserStub());
        $provider->shouldReceive('validateCredentials')->withAnyArgs()->andReturn(false);
        $guard = new Guard('jwt', $provider, $this->getRequest());
        $this->assertFalse($guard->validate(['user' => 'test', 'password' => 'test']));
    }

    public function testSetRequest()
    {
        $provider = Mockery::mock(UserProvider::class);
        $guard = new Guard('jwt', $provider, $this->getRequest());
        $newRequest = $this->getRequest();
        $guard->setRequest($newRequest);
        $this->assertEquals($guard->getRequest(), $newRequest);
    }

    public function testAttempt()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')->andReturn(new Stubs\UserStub());
        $provider->shouldReceive('validateCredentials')->withAnyArgs()->andReturn(true);
        $guard = new Guard('jwt', $provider, $this->getRequest());
        $token = $guard->attempt(['user' => 'test', 'password' => 'test']);
        $this->assertTrue($token instanceof Token);
    }

    public function testCustomAdapterConfig()
    {
        $config = ['adapter' => ['issuer' => 'http://special.case']];
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')->andReturn(new Stubs\UserStub());
        $provider->shouldReceive('validateCredentials')->withAnyArgs()->andReturn(true);
        $guard = new Guard('jwt', $provider, $this->getRequest(), $config);
        $token = $guard->attempt(['user' => 'test', 'password' => 'test']);
        $this->assertEquals($config['adapter']['issuer'], $token->getClaim('iss'));
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
        $guard = new Guard('jwt', $provider, $this->getRequest());
        $token = $guard->attempt(['user' => 'test', 'password' => 'test']);
    }


    public function testBadAttempt()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')->andReturn(new Stubs\UserStub());
        $provider->shouldReceive('validateCredentials')->withAnyArgs()->andReturn(false);
        $guard = new Guard('jwt', $provider, $this->getRequest());
        $token = $guard->attempt(['user' => 'test', 'password' => 'test']);
        $this->assertFalse($token);
    }

    /**
    * @expectedException Canis\Lumen\Jwt\Exceptions\InvalidTokenException
    */
    public function testBadUserAttempt()
    {
        $provider = Mockery::mock(UserProvider::class);
        $provider->shouldReceive('retrieveByCredentials')->andReturn(new Stubs\BadUserStub());
        $provider->shouldReceive('validateCredentials')->withAnyArgs()->andReturn(true);
        $guard = new Guard('jwt', $provider, $this->getValidTokenRequest());
        $token = $guard->attempt(['user' => 'test', 'password' => 'test']);
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
