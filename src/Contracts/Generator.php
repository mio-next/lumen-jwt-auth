<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt\Contracts;

use Canis\Lumen\Jwt\Token;

interface Generator
{
    /**
     * Generates new token from a set of claims
     * @param  array  $claims
     * @return Token
     */
    public function __invoke(array $claims);
}
