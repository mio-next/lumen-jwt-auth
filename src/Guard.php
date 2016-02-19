<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Canis\Lumen\Jwt\Contracts\Subject as SubjectContract;

class Guard
    extends BaseGuard
    implements GuardInterface
{

    /**
     * @inheritdoc
     */
    public function refresh(AuthFactory $auth)
    {
        $token = $this->getBearerToken(true);
        if ($token !== false && $token->hasClaim(static::JWT_GUARD_CLAIM)) {
            $guard = $token->getClaim(static::JWT_GUARD_CLAIM);
            return $auth->guard($guard)->refreshToken($token);
        }
        return false;
    }

    /**
     * Refresh the token 
     * @param  Token  $token
     * @return Token|boolean  New token or false if old token can't be verified
     */
    public function refreshToken(Token $token)
    {
        $user = $this->getProvider()->retrieveById($token->getClaim('sub'));
        $claimValidation = [static::JWT_GUARD_CLAIM => $this->id];
        if (!($user instanceof SubjectContract)
            || !$token->ensureClaimValues(array_merge($user->getJWTClaimValidation(), $claimValidation))) {
            return false;
        }
        return $this->generateToken($user);
    }


    /**
     * @inheritdoc
     */
    public function universalUserLogin(AuthFactory $auth)
    {
        $token = $this->getBearerToken();
        $guard = false;
        if ($token !== false && $token->hasClaim(static::JWT_GUARD_CLAIM)) {
            $guard = $token->getClaim(static::JWT_GUARD_CLAIM);
            $user = $auth->guard($guard)->user();
            if ($user === null) {
                $guard = false;
            }
        }
        return $guard;
    }
}
