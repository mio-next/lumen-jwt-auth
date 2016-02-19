<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace CanisUnit\Lumen\Jwt\Adapters\Lcobucci;

use CanisUnit\Lumen\Jwt\BaseTestCase;
use Canis\Lumen\Jwt\Adapters\Lcobucci\ValidationData;

class ValidationDataTest extends BaseTestCase
{
    public function testConstruct()
    {
        $time = time() - 10;
        $validation = new ValidationData($time);
        $this->assertEquals($validation->get('jti'), null);
        $this->assertEquals($validation->get('iss'), null);
        $this->assertEquals($validation->get('aub'), null);
        $this->assertEquals($validation->get('sub'), null);
        $this->assertEquals($validation->get('iat'), $time);
        $this->assertEquals($validation->get('nbf'), $time);
        $this->assertEquals($validation->get('exp'), $time);
    }

    public function testSetId()
    {
        $validation = new ValidationData();
        $validation->setId('test');
        $this->assertEquals($validation->get('jti'), 'test');
    }

    public function testSetIssuer()
    {
        $validation = new ValidationData();
        $validation->setIssuer('test');
        $this->assertEquals($validation->get('iss'), 'test');
    }


    public function testSetAudience()
    {
        $validation = new ValidationData();
        $validation->setAudience('test');
        $this->assertEquals($validation->get('aud'), 'test');
    }


    public function testSetSubject()
    {
        $validation = new ValidationData();
        $validation->setSubject('test');
        $this->assertEquals($validation->get('sub'), 'test');
    }

    public function testSetCurrentTime()
    {
        $time = time() - 10;
        $validation = new ValidationData();
        $validation->setCurrentTime($time);
        $this->assertEquals($validation->get('iat'), $time);
        $this->assertEquals($validation->get('nbf'), $time);
        $this->assertEquals($validation->get('exp'), $time);
    }

    public function testSetExpiration()
    {
        $time = time() - 10;
        $validation = new ValidationData();
        $validation->setExpiration($time);
        $this->assertEquals($validation->get('exp'), $time);
    }


    public function testHas()
    {
        $validation = new ValidationData();
        $this->assertTrue($validation->has('exp'));
    }
}
