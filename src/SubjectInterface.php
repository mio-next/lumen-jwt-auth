<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt;

interface SubjectInterface
{
    public function getJWTSubject();

    public function getJWTSubjectType();

    public function getJWTClaims();
}
