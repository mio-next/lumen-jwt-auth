<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt;

use Auth;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\Authenticatable;
use Exceptions\InvalidTokenException;

abstract class BaseJwtGuard
    implements Guard, JwtGuardInterface
{
    use GuardHelpers;

    private $request;
    private $providerIdentifier;

    public function __construct($provider, Request $request)
    {
        $this->request = $request;
        $this->providerIdentifier = $provider;
        $this->provider = Auth::createUserProvider($provider);
    }

    protected function getTokenProcessor()
    {
        $config = config('jwt');
        return new JwtParser($config);
    }

    protected function getGenerator()
    {
        $config = config('jwt');
        return new JwtGenerator($config);
    }

    /**
     * @inheritdoc
     */
    public function user()
    {
        if (!is_null($this->user)) {
            return $this->user;
        }
        $user = null;
        $token = $this->getBearerToken();
        if ($token !== false) {
            $user = $this->provider->retrieveById($token->getClaim('sub'));
        }
        return $this->user = $user;
    }

    public function getBearerToken()
    {
        $authHeader = $this->request->headers->get('Authorization');
        if (empty($authHeader)) {
            return false;
        }
        if (!Str::startsWith(strtolower($authHeader), 'bearer')) {
            return false;
        }
        $token = trim(str_ireplace('bearer', '', $authHeader));
        $processor = $this->getTokenProcessor();
        return $processor($token);
    }

    /**
     * @inheritdoc
     */
    public function validate(array $credentials = [])
    {
        $user = $this->provider->retrieveByCredentials($credentials);
        if ($this->hasValidCredentials($user, $credentials)) {
            return true;
        }
        return false;
    }

    public function setRequest(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function attempt(array $credentials = [])
    {
        $user = $this->provider->retrieveByCredentials($credentials);
        if ($this->hasValidCredentials($user, $credentials)) {
            $tokenGenerator = $this->getGenerator();
            $claims = $user->getJWTClaims();
            $claims['sub'] = $user->getJWTSubject();
            $claims['type'] = $this->providerIdentifier;
            if (!($token = $tokenGenerator($claims))) {
                throw new InvalidTokenException("Unable to generate token");
            }
            return $token;
        }
        return false;
    }
}
