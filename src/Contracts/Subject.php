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
     * Gets the type of subject
     * 
     * @return string
     */
    public function getJWTSubjectProvider();

    /**
     * [getJWTClaims description]
     * @return [type] [description]
     */
    public function getJWTClaims();
}
