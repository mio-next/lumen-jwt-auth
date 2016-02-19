<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace CanisUnit\Lumen\Jwt\Adapters\Lcobucci;

use CanisUnit\Lumen\Jwt\BaseTestCase;
use Canis\Lumen\Jwt\Adapters\Lcobucci\Factory;
use Canis\Lumen\Jwt\Adapters\Lcobucci\Generator;
use Canis\Lumen\Jwt\Token;
use Canis\Lumen\Jwt\Exceptions\InvalidTokenException;

class GeneratorTest extends BaseTestCase
{
  /**
    * @expectedException Canis\Lumen\Jwt\Exceptions\InvalidTokenException
    */
    public function testNoSecret()
    {
        $factory = new Factory([]);
        $generator = $factory->getGenerator();
        $token = $generator(['sub' => 'test']);
    }

    public function testGenerator()
    {
        $factory = new Factory($this->getJwtConfig());
        $generator = $factory->getGenerator();
        $token = $generator(['sub' => 'test']);
        $this->assertTrue($token instanceof Token);
    }

    public function testBadClaim()
    {
        $factory = new Factory($this->getJwtConfig());
        $generator = $factory->getGenerator();
        $token = $generator(['jti' => 'test', 'sub' => 'test']);
        $this->assertTrue($token instanceof Token);
    }

    public function testAudience()
    {
        $audience = 'AAA';
        $factory = new Factory($this->getJwtConfig($this->getJwtConfig(['audience' => $audience])));
        $generator = $factory->getGenerator();
        $token = $generator(['sub' => 'test']);
        $this->assertTrue($token instanceof Token);
        $this->assertEquals($audience, $token->getClaim('aud'));
    }


    public function testIssuer()
    {
        $issuer = 'AAA.com';
        $factory = new Factory($this->getJwtConfig($this->getJwtConfig(['issuer' => $issuer])));
        $generator = $factory->getGenerator();
        $token = $generator(['sub' => 'test']);
        $this->assertTrue($token instanceof Token);
        $this->assertEquals($issuer, $token->getClaim('iss'));
    }

   public function testNoSubject()
   {
        $factory = new Factory($this->getJwtConfig($this->getJwtConfig()));
        $generator = $factory->getGenerator();
        $this->assertFalse($generator([]));
   }
}
