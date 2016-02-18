<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */

namespace Canis\Lumen\Jwt;

class Token
{
    /**
     * @var array
     */
    private $claims;
    /**
     * @var string
     */
    private $tokenString;

    /**
     * Constructor
     * @param string $tokenString
     * @param array  $claims
     */
    public function __construct($tokenString, $claims = [])
    {
        $this->tokenString = $tokenString;
        $this->claims = $claims;
    }

    /**
     * Get a specific claim
     * @param  string $claim Name of claim
     * @return mixed         Null on not found
     */
    public function getClaim($claim)
    {
        if (isset($this->claims[$claim])) {
            return $this->claims[$claim];
        }
        return null;
    }


    /**
     * Check for a specific claim
     * @param  string $claim Name of claim
     * @return mixed         Null on not found
     */
    public function hasClaim($claim)
    {
        return array_key_exists($claim, $this->claims);
    }

    /**
     * Get all claims
     * 
     * @return array
     */
    public function getClaims()
    {
        return $this->claims;
    }

    /**
     * Get token string
     * @return string String variant of token
     */
    public function getTokenString()
    {
        return $this->tokenString;
    }

    /**
     * Convert object to string
     * @return string String variant of token
     */
    public function __toString()
    {
        return $this->tokenString;
    }
}
