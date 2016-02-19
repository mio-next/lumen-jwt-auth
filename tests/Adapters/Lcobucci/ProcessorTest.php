<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace CanisUnit\Lumen\Jwt\Adapters\Lcobucci;

use CanisUnit\Lumen\Jwt\BaseTestCase;
use Canis\Lumen\Jwt\Adapters\Lcobucci\Processor;
use Canis\Lumen\Jwt\Exceptions\InvalidTokenException;
use Canis\Lumen\Jwt\Token;

class ProcessorTest extends BaseTestCase
{

    public function testAudience()
    {
        $audience = 'AAA';
        $config = ['audience' => $audience];
        $testToken = $this->getValidToken($config);
        $tokenStr = (string) $testToken;
        $parser = new Processor($this->getJwtConfig($config));
        define('JWT_DEBUG', true);
        $token = $parser($tokenStr);
        $this->assertEquals($testToken->getClaim('aud'), $token->getClaim('aud'));
    }


    public function testIssuer()
    {
        $issuer = 'AAA.com';
        $config = ['issuer' => $issuer];
        $testToken = $this->getValidToken($config);
        $tokenStr = (string) $testToken;
        $parser = new Processor($this->getJwtConfig($config));
        $token = $parser($tokenStr);
        $this->assertEquals($testToken->getClaim('iss'), $token->getClaim('iss'));
    }

    public function testModifiedToken()
    {
        $tokenStr = (string) $this->getValidToken();
        $tokenStr .= 'a';
        $parser = new Processor($this->getJwtConfig());
        $token = $parser($tokenStr);
        $this->assertFalse($token);
    }

    public function testRefreshTokenOld()
    {
        $tokenStr = (string) $this->getExpiredToken(-2);
        $parser = new Processor($this->getJwtConfig(['refreshOffsetAllowance' => 1]));
        $token = $parser($tokenStr, true);
        $this->assertFalse($token);
    }

    public function testRefreshTokenExpired()
    {
        $token = $this->getExpiredToken(0);
        $tokenStr = (string) $token;
        $parser = new Processor($this->getJwtConfig(['refreshOffsetAllowance' => 2]));
        $tokenResult = $parser($tokenStr, true);
        $this->assertEquals($token->getClaim('jti'), $tokenResult->getClaim('jti'));
    }

    public function testRefreshTokenFresh()
    {
        $token = $this->getExpiredToken(5);
        $tokenStr = (string) $token;
        $parser = new Processor($this->getJwtConfig(['refreshOffsetAllowance' => 2]));
        $tokenResult = $parser($tokenStr, true);
        $this->assertEquals($token->getClaim('jti'), $tokenResult->getClaim('jti'));
    }

    public function testOldToken()
    {
        $tokenStr = (string) $this->getExpiredToken();
        $parser = new Processor($this->getJwtConfig());
        $token = $parser($tokenStr);
        $this->assertFalse($token);
    }

    public function testNotReadyToken()
    {
        $tokenStr = (string) $this->getNotReadyToken();
        $parser = new Processor($this->getJwtConfig());
        $token = $parser($tokenStr);
        $this->assertFalse($token);
    }

    public function testTokenWithoutClaims()
    {
        $tokenStr = (string) $this->getNotReadyToken();
        $parser = new Processor($this->getJwtConfig(['requiredClaims' => ['boooom']]));
        $token = $parser($tokenStr);
        $this->assertFalse($token);
    }
}
