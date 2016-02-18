<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt\Contracts;

interface Subject
{
    /**
     * Gets the ID for the subject
     *
     * @return mixed
     */
    public function getJWTSubject();

    /**
     * Get the claims
     *
     * @return array
     */
    public function getJWTClaims();
}
