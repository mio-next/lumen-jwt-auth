<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt\Adapters\Lcobucci;

use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Parser;
use Canis\Lumen\Jwt\Token;
use Canis\Lumen\Jwt\Contracts\Generator as GeneratorContract;

class Generator
    extends HelperBase
    implements GeneratorContract
{
    /**
     * Generates the token
     * @param  array $claims
     * @return string
     */
    final public function __invoke(array $claims)
    {
        $signer = new Sha256();
        $builder = new Builder();
        $claims = array_merge($this->getDefaultClaims(), $claims, $this->getForcedClaims());
        if (!$this->checkRequiredClaims(array_keys($claims))) {
            return false;
        };
        foreach ($claims as $claim => $value) {
            if ($this->isBadClaim($claim)) {
                continue;
            }
            $builder->set($claim, $value);
        }
        $builder->setId(substr(hash('sha256', serialize($claims) . openssl_random_pseudo_bytes(20)), 0, 16), $this->config['jtiInHeader']);
        $builder->sign($signer, $this->config['secret']);
        $token = $builder->getToken();
        return new Token((string) $token, $token->getClaims());
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
        if (!empty($this->config['audience'])) {
            $default['aud'] = $this->config['audience'];
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
