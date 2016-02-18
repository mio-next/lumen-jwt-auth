<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace CanisUnit\Lumen\Jwt\Stubs;

use Canis\Lumen\Jwt\Contracts\Subject as JwtSubjectInterface;
use Illuminate\Http\Request;
use Illuminate\Auth\Authenticatable;
use Laravel\Lumen\Auth\Authorizable;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Auth\Access\Authorizable as AuthorizableContract;

class UserStub implements
    AuthenticatableContract,
    AuthorizableContract,
    JwtSubjectInterface
{
    use Authenticatable, Authorizable;
    
    public function getJWTClaims()
    {
        return [
            'test' => 'claim'
        ];
    }

    public function getJWTSubject()
    {
        return 'user-test-1';
    }
}