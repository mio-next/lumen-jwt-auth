<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt\Adapters;

use Canis\Lumen\Jwt\Contracts\AdapterFactory;

abstract class AbstractFactory
    implements AdapterFactory
{
    private $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    protected function getConfig()
    {
        return $this->config;
    }

}
