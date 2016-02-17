<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt\Contracts;

interface AdapterFactory
{
    public function getGenerator();
    public function getProcessor();
}
