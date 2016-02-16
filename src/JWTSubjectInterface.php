<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt;

interface JwtSubjectInterface
{
    public function getJWTSubject();

    public function getJWTClaims();
}
