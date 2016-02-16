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
use Lcobucci\JWT\Token;

class JwtGenerator
    extends JwtHelperBase
{
    /**
     * Generates the token
     * @param  array $claims
     * @return Token
     */
    final public function __invoke($claims)
    {
        $signer = new Sha256();
        $builder = new Builder();
        $claims = array_merge($this->getDefaultClaims(), $claims, $this->getForcedClaims());
        if (!$this->checkRequiredClaims(array_keys($claims))) {
            throw new InvalidTokenException("Attempted to create token without required claims");
        };
        foreach ($claims as $claim => $value) {
            if ($this->isBadClaim($claim)) {
                continue;
            }
            $builder->set($claim, $value);
        }
        $builder->setId(substr(hash('sha256', serialize($claims) . openssl_random_pseudo_bytes(20)), 0, 16), true);
        $builder->sign($signer, $this->config['secret']);
        return $builder->getToken();
    }

    /**
     * Default claims (can be overriden)
     *
     * @return array
     */
    protected function getDefaultClaims()
    {
        $default = [];
        if (!empty($this->config['issuer'])) {
            $default['iss'] = $this->config['issuer'];
        }
        return $default;
    }

    /**
     * Forced claims
     *
     * @return array
     */
    private function getForcedClaims()
    {
        return [
            'iat' => time(),
            'nbf' => time() + $this->config['nbfOffset'],
            'exp' => time() + $this->config['expOffset']
        ];
    }

    /**
     * Checks if claim is bad
     *
     * @param  string  $claim
     * @return boolean
     */
    private function isBadClaim($claim)
    {
        return in_array($claim, ['jti']);
    }
}
