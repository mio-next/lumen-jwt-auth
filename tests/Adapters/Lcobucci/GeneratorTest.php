<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace CanisUnit\Lumen\Jwt\Adapters\Lcobucci;

use CanisUnit\Lumen\Jwt\BaseTestCase;
use Canis\Lumen\Jwt\Adapters\Lcobucci\Generator;
use Canis\Lumen\Jwt\Exceptions\InvalidTokenException;

class GeneratorTest extends BaseTestCase
{
  /**
    * @expectedException Canis\Lumen\Jwt\Exceptions\InvalidTokenException
    */
    public function testNoSecret()
    {
        $generator = new Generator([]);
        $token = $generator(['sub' => 'test']);
    }

    public function testGenerator()
    {
        $generator = new Generator($this->getJwtConfig());
        $token = $generator(['sub' => 'test']);
        $this->assertTrue($token instanceof \Lcobucci\JWT\Token);
    }

    public function testBadClaim()
    {
        $generator = new Generator($this->getJwtConfig());
        $token = $generator(['jti' => 'test', 'sub' => 'test']);
        $this->assertTrue($token instanceof \Lcobucci\JWT\Token);
    }

    public function testAudience()
    {
        $audience = 'AAA';
        $generator = new Generator($this->getJwtConfig(['audience' => $audience]));
        $token = $generator(['sub' => 'test']);
        $this->assertTrue($token instanceof \Lcobucci\JWT\Token);
        $this->assertEquals($audience, $token->getClaim('aud'));
    }


    public function testIssuer()
    {
        $issuer = 'AAA.com';
        $generator = new Generator($this->getJwtConfig(['issuer' => $issuer]));
        $token = $generator(['sub' => 'test']);
        $this->assertTrue($token instanceof \Lcobucci\JWT\Token);
        $this->assertEquals($issuer, $token->getClaim('iss'));
    }

   public function testNoSubject()
   {
       $generator = new Generator($this->getJwtConfig());
       $this->assertFalse($generator([]));
   }
}
