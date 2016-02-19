<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt\Adapters\Lcobucci;

use Canis\Lumen\Jwt\Token;
use Canis\Lumen\Jwt\Contracts\Processor as ProcessorContract;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token as JwtToken;

class Processor
    extends HelperBase
    implements ProcessorContract
{

    /**
     * @inheritdoc
     */
    final public function __invoke($tokenString)
    {
        $token = (new Parser())->parse((string) $tokenString);
        $signer = new Sha256();
        $claims = $token->getClaims();
        if (
                !$token->verify($signer, $this->config['secret']) 
            ||  !$this->checkRequiredClaims(array_keys($claims))
            ||  !$this->validateToken($token)
        ) {
            return false;
        };
        foreach ($claims as $key => $value) {
            $claims[$key] = $value->getValue();
        }
        return new Token((string) $token, $claims);
    }

    /**
     * Validate token with validation data
     * 
     * @param  JwtToken $token
     * @return boolean
     */
    private function validateToken(JwtToken $token)
    {
        $data = new ValidationData();
        if (isset($this->config['issuer'])) {
            $data->setIssuer($this->config['issuer']);
        }
        if (isset($this->config['audience'])) {
            $data->setAudience($this->config['audience']);
        }
        if (!$token->validate($data)) {
            return false;
        }
        return true;
    }
}
