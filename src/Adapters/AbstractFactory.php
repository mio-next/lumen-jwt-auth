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
    /**
     * @var array Factory configuration
     */
    private $config;

    /**
     * Constructor.
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    /**
     * Get config
     * @return array
     */
    protected function getConfig()
    {
        return $this->config;
    }

}
