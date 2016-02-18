<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace CanisUnit\Lumen\Jwt;

use Canis\Lumen\Jwt\Token;

class TokenTest extends BaseTestCase
{
    const TEST_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImp0aSI6IjBlMDMzMDdlYzE0NDcwMDEifQ.eyJpc3MiOiJodHRwOlwvXC9jaG1zLWFwaS5kb2NrZXIiLCJzdWIiOiIxZDFjMjY2ZS1kYTNkLTQ0NjctOGRiNC05YjM1YzY4YzQ3ZDgiLCJ0eXBlIjoidXNlcnMiLCJpYXQiOjE0NTU2Njk1OTQsIm5iZiI6MTQ1NTY2OTU5NCwiZXhwIjoxNDU1NjczMTk0LCJqdGkiOiIwZTAzMzA3ZWMxNDQ3MDAxIn0.9RxvGUpdJnbW5PUhTuBKMscUUoh9Ho69HHa3TTHBYNA';

    private function getBasicToken($claims = [])
    {
        return new Token(static::TEST_TOKEN, $claims);
    }

    public function testGetClaim()
    {
        $token = $this->getBasicToken(['test' => 'claim']);
        $this->assertEquals($token->getClaim('test'), 'claim');
        $this->assertEquals($token->getClaim('boom'), null);
    }


    public function testHasClaim()
    {
        $token = $this->getBasicToken(['test' => 'claim']);
        $this->assertTrue($token->hasClaim('test'));
        $this->assertFalse($token->hasClaim('boom'));
    }

    public function testGetClaims()
    {
        $claims = ['test' => 'claim'];
        $token = $this->getBasicToken($claims);
        $this->assertEquals($token->getClaims(), $claims);
    }

    public function testToString()
    {
        $token = $this->getBasicToken();
        $this->assertEquals((string)$token, static::TEST_TOKEN);
        $this->assertEquals($token->getTokenString(), static::TEST_TOKEN);
    }
}
