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
        $jti = substr(hash('sha256', serialize($claims) . openssl_random_pseudo_bytes(20)), 0, 16);
        $builder->setId($jti, $this->config['jtiInHeader']);
        $builder->sign($signer, $this->config['secret']);
        $token = $builder->getToken();
        $generatedClaims = $token->getClaims();
        foreach ($generatedClaims as $key => $value) {
            $generatedClaims[$key] = $value->getValue();
        }
        return new Token((string) $token, $generatedClaims);
    }

    /**
     * Default claims (can be overriden)
     *
     * @return array
     */
    protected function getDefaultClaims()
    {
        $default = [];
        $default['nbf'] = time() + $this->config['nbfOffset'];
        $default['exp'] = time() + $this->config['expOffset'];
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
            'iat' => time()
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
