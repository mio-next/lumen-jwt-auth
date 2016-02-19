<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt\Adapters\Lcobucci;

use Canis\Lumen\Jwt\Exceptions\InvalidTokenException;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;

abstract class HelperBase
{
    /**
     * @var array
     */
    protected $config = [];

    /**
     * Constructor
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        $this->config = $config;
        if (empty($this->config['secret'])) {
            throw new InvalidTokenException("JWT token generator requires a secret");
        }
    }

    /**
     * Checks for all required claims
     *
     * @param  array $claimKeys
     * @return boolean
     */
    final protected function checkRequiredClaims($claimKeys)
    {
        $claimKeys[] = 'jti';
        return count(array_diff($this->config['requiredClaims'], $claimKeys)) === 0;
    }
}
