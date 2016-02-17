<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace CanisUnit\Lumen\Jwt\Stubs;

use Canis\Lumen\Jwt\SubjectInterface as JwtSubjectInterface;

class UserStub implements JwtSubjectInterface
{
    public function getJWTSubject()
    {
        return 'user-test-1';
    }

    public function getJWTClaims()
    {
        return [
            'test' => 'claim'
        ];
    }
}