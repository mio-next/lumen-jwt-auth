<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt;

use Exceptions\InvalidTokenException;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Parser;

class JwtParser
    extends JwtHelperBase
{
    /**
     * Parses and validates token
     * @param  string $tokenString
     * @return Token
     */
    final public function __invoke($tokenString)
    {
        $token = (new Parser())->parse((string) $tokenString);
        $signer = new Sha256();
        if (!$token->verify($signer, $this->config['secret'])) {
            return false;
        }
        if (!$this->checkRequiredClaims(array_keys($token->getClaims()))) {
            return false;
        };
        return $token;
    }
}
