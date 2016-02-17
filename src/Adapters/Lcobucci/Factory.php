<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt\Adapters\Lcobucci;

use Canis\Lumen\Jwt\Adapters\AbstractFactory;

class Factory
    extends AbstractFactory
{
    /**
     * @inheritdoc
     */
    public function getProcessor()
    {
        return new Processor($this->getConfig());
    }

    /**
     * @inheritdoc
     */
    public function getGenerator()
    {
        return new Generator($this->getConfig());
    }
}
