<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt\Contracts;

use Canis\Lumen\Jwt\Token;

interface Processor
{
    /**
     * Processes a string token
     * @param  string  $tokenString
     * @return Token|boolean
     */
    public function __invoke($tokenString);
}
