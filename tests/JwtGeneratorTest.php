<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace CanisUnit\Lumen\Jwt;

use Canis\Lumen\Jwt\JwtGenerator;
use Canis\Lumen\Jwt\Exceptions\InvalidTokenException;

class JwtGeneratorTest extends BaseTestCase
{
  /**
    * @expectedException Canis\Lumen\Jwt\Exceptions\InvalidTokenException
    */
    public function testNoSecret()
    {
        $generator = new JwtGenerator([]);
        $token = $generator(['sub' => 'test']);
    }

    public function testGenerator()
    {
        $generator = new JwtGenerator($this->getConfig());
        $token = $generator(['sub' => 'test']);
        $this->assertTrue($token instanceof \Lcobucci\JWT\Token);
    }

    public function testBadClaim()
    {
        $generator = new JwtGenerator($this->getConfig());
        $token = $generator(['jti' => 'test', 'sub' => 'test']);
        $this->assertTrue($token instanceof \Lcobucci\JWT\Token);
    }

    public function testAudience()
    {
        $audience = 'AAA';
        $generator = new JwtGenerator($this->getConfig(['audience' => $audience]));
        $token = $generator(['sub' => 'test']);
        $this->assertTrue($token instanceof \Lcobucci\JWT\Token);
        $this->assertEquals($audience, $token->getClaim('aud'));
    }


    public function testIssuer()
    {
        $issuer = 'AAA.com';
        $generator = new JwtGenerator($this->getConfig(['issuer' => $issuer]));
        $token = $generator(['sub' => 'test']);
        $this->assertTrue($token instanceof \Lcobucci\JWT\Token);
        $this->assertEquals($issuer, $token->getClaim('iss'));
    }

    /**
    * @expectedException Canis\Lumen\Jwt\Exceptions\InvalidTokenException
    */
   public function testNoSubject()
   {
       $generator = new JwtGenerator($this->getConfig());
       $token = $generator([]);
   }
}
