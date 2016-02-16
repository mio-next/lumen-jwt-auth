<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt;

use Canis\Lumen\Jwt\Exceptions\InvalidTokenException;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;

abstract class JwtHelperBase
{
    /**
     * @var array
     */
    protected $config = [];

    /**
     * Constructor
     * @param array $config
     */
    public function __construct($config = [])
    {
        $this->config = array_merge($this->getDefaultConfig(), $config);

        if (empty($this->config['secret'])) {
            throw new InvalidTokenException("JWT token generator requires a secret");
        }
    }

    /**
     * Default configuration
     *
     * @return array
     */
    final protected function getDefaultConfig()
    {
        return [
            'expOffset' => 3600,
            'nbfOffset' => 0,
            'requiredClaims' => ['iat', 'exp', 'nbf', 'sub', 'jti']
        ];
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
