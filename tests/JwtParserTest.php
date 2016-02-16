<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace CanisUnit\Lumen\Jwt;

use Canis\Lumen\Jwt\JwtParser;
use Canis\Lumen\Jwt\Exceptions\InvalidTokenException;

class JwtParserTest extends BaseTestCase
{

    public function testAudience()
    {
        $audience = 'AAA';
        $config = ['audience' => $audience];
        $testToken = $this->getValidToken($config);
        $tokenStr = (string) $testToken;
        $parser = new JwtParser($this->getConfig($config));
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
        $parser = new JwtParser($this->getConfig($config));
        $token = $parser($tokenStr);
        $this->assertEquals($testToken->getClaim('iss'), $token->getClaim('iss'));
    }

    public function testModifiedToken()
    {
        $tokenStr = (string) $this->getValidToken();
        $tokenStr .= 'a';
        $parser = new JwtParser($this->getConfig());
        $token = $parser($tokenStr);
        $this->assertFalse($token);
    }

    public function testOldToken()
    {
        $tokenStr = (string) $this->getExpiredToken();
        $parser = new JwtParser($this->getConfig());
        $token = $parser($tokenStr);
        $this->assertFalse($token);
    }

    public function testNotReadyToken()
    {
        $tokenStr = (string) $this->getNotReadyToken();
        $parser = new JwtParser($this->getConfig());
        $token = $parser($tokenStr);
        $this->assertFalse($token);
    }

    public function testTokenWithoutClaims()
    {
        $tokenStr = (string) $this->getNotReadyToken();
        $parser = new JwtParser($this->getConfig(['requiredClaims' => ['boooom']]));
        $token = $parser($tokenStr);
        $this->assertFalse($token);
    }
}
