<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt\Contracts;

interface AdapterFactory
{
    /**
     * Get generator
     * @return Generator
     */
    public function getGenerator();

    /**
     * Get processor
     * @return Processor
     */
    public function getProcessor();
}
